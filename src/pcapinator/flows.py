"""Flow assembly: the per-conversation view every detector consumes.

Frames arrive in capture order and are folded into flows keyed on the
conversation rather than on the direction, so both halves of a session
accumulate into one record oriented initiator first.

The table is bounded on purpose. Detection runs over multi-gigabyte captures,
so no packet is retained, idle flows are expired against the capture's own
clock as it advances, and a hard ceiling evicts the least recently active
conversation when a capture presents more concurrent flows than that. A SYN
flood from spoofed source ports does exactly that, and it is precisely the
traffic a scan detector is pointed at, so the ceiling is a memory guarantee
rather than an optimisation.

A TCP connection that resets or tears down cleanly is finished at that point
rather than at its timeout, and a later packet on the same five-tuple opens a
new flow. That is what makes repeated C2 callbacks to one server surface as
many short connections instead of one long-lived conversation.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from typing import Iterable, Iterator

from .layers.types import (
    IPPROTO_TCP,
    TCP_FIN,
    TCP_RST,
    TCP_SYN,
    Flow,
    FlowKey,
    Frame,
)

DEFAULT_MAX_FLOWS = 1 << 18

_Endpoint = tuple[str, int]
_Canon = tuple[int, _Endpoint, _Endpoint]


class _State:
    """Per-flow bookkeeping that is not part of the emitted Flow."""

    __slots__ = ("flow", "oriented", "fin_out", "fin_in", "closing")

    def __init__(self, flow: Flow, oriented: bool) -> None:
        self.flow = flow
        self.oriented = oriented
        self.fin_out = False
        self.fin_in = False
        self.closing = False


class FlowTable:
    """Folds frames into flows, emitting each one once it is finished or idle.

    tcp_timeout and udp_timeout are idle timeouts measured on capture
    timestamps. Non-TCP protocols, including ICMP and IP fragments, use
    udp_timeout.
    """

    def __init__(self, tcp_timeout: float = 300.0, udp_timeout: float = 60.0,
                 *, max_flows: int = DEFAULT_MAX_FLOWS) -> None:
        if tcp_timeout <= 0 or udp_timeout <= 0:
            raise ValueError("timeouts must be positive")
        if max_flows < 1:
            raise ValueError("max_flows must be at least 1")
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.max_flows = max_flows
        # Insertion order is activity order: every touched flow moves to the
        # end, so expiry only ever inspects the front of each table.
        self._tcp: OrderedDict[_Canon, _State] = OrderedDict()
        self._other: OrderedDict[_Canon, _State] = OrderedDict()
        self._ready: list[Flow] = []
        self._clock = -math.inf

    def __len__(self) -> int:
        """Flows currently held in memory."""
        return len(self._tcp) + len(self._other)

    @property
    def ready(self) -> int:
        """Finished flows waiting to be collected by expire() or close()."""
        return len(self._ready)

    def add(self, frame: Frame) -> None:
        if frame.ts > self._clock:
            self._clock = frame.ts

        is_tcp = frame.proto == IPPROTO_TCP
        table = self._tcp if is_tcp else self._other
        timeout = self.tcp_timeout if is_tcp else self.udp_timeout
        src, dst = _endpoints(frame)
        canon = _canon(frame.proto, src, dst)
        state = table.get(canon)

        if state is not None and self._reuses_tuple(state, frame, timeout):
            self._finish(table, canon, state)
            state = None

        if state is None:
            state = _State(*_open_flow(frame, canon, src, dst))
            table[canon] = state
        else:
            _reorient(state, frame, src, dst)

        flow = state.flow
        outbound = src == (flow.key.src, flow.key.sport)

        if frame.ts < flow.start:
            flow.start = frame.ts
        if frame.ts > flow.end:
            flow.end = frame.ts
        if outbound:
            flow.packets_out += 1
            flow.bytes_out += frame.wirelen
            flow.payload_out += len(frame.payload)
        else:
            flow.packets_in += 1
            flow.bytes_in += frame.wirelen
            flow.payload_in += len(frame.payload)
            flow.responded = True
        flow.flags_seen |= frame.flags
        table.move_to_end(canon)

        if frame.proto == IPPROTO_TCP:
            if frame.flags & TCP_RST:
                self._finish(table, canon, state)
            elif frame.flags & TCP_FIN:
                if outbound:
                    state.fin_out = True
                else:
                    state.fin_in = True
                state.closing = state.fin_out and state.fin_in
            elif state.closing:
                # Both sides have finished; this is the ACK that completes the
                # teardown. Waiting for it keeps that ACK out of a new flow.
                self._finish(table, canon, state)

        self._sweep()
        self._enforce_cap()

    def _reuses_tuple(self, state: _State, frame: Frame, timeout: float) -> bool:
        """Whether this frame belongs to a new conversation on an old tuple.

        Two things end the previous one. An idle gap wider than the timeout,
        checked here rather than left to the ordered sweep because a tuple whose
        own traffic is the only thing advancing the capture clock is never at
        the front of the table when its gap opens: an ICMP tunnel or a
        fixed-source-port UDP beacon would otherwise fold every callback into
        one endless flow and erase the interval it is detected by.

        And a SYN once either side has sent a FIN. A SYN cannot retransmit on a
        connection that reached teardown, so it opens a new one; without this a
        tuple reused before the last FIN was captured merges two connections.
        """
        if self._clock - state.flow.end >= timeout:
            return True
        return bool(frame.flags & TCP_SYN) and (state.fin_out or state.fin_in)

    def expire(self, now: float) -> list[Flow]:
        """Collect flows idle past their timeout as of now.

        Flows already finished by a reset or a completed teardown, and flows
        evicted to hold the table under its ceiling, come out here too: this is
        the one place a caller collects completed work.
        """
        if now > self._clock:
            self._clock = now
        self._sweep()
        return self._drain()

    def close(self) -> list[Flow]:
        """Drain every remaining flow, however recently it was active."""
        for table in (self._tcp, self._other):
            self._ready.extend(state.flow for state in table.values())
            table.clear()
        return self._drain()

    def _drain(self) -> list[Flow]:
        ready, self._ready = self._ready, []
        return ready

    def _finish(self, table: OrderedDict[_Canon, _State], canon: _Canon,
                state: _State) -> None:
        del table[canon]
        self._ready.append(state.flow)

    def _sweep(self) -> None:
        for table, timeout in ((self._tcp, self.tcp_timeout),
                               (self._other, self.udp_timeout)):
            while table:
                canon, state = next(iter(table.items()))
                # Capture timestamps are not guaranteed monotonic across
                # interfaces, so a front entry that looks fresh only defers
                # expiry to a later sweep; it never emits a live flow.
                if self._clock - state.flow.end < timeout:
                    break
                self._finish(table, canon, state)

    def _enforce_cap(self) -> None:
        while len(self) > self.max_flows:
            if not self._tcp:
                table = self._other
            elif not self._other:
                table = self._tcp
            else:
                tcp_end = next(iter(self._tcp.values())).flow.end
                other_end = next(iter(self._other.values())).flow.end
                table = self._tcp if tcp_end <= other_end else self._other
            canon, state = next(iter(table.items()))
            self._finish(table, canon, state)


def assemble(frames: Iterable[Frame], **kw) -> Iterator[Flow]:
    """Yield flows as the frames complete or expire them.

    Keyword arguments are passed to FlowTable. Frames are expected in capture
    order; flows come out in completion order, not start order.
    """
    table = FlowTable(**kw)
    for frame in frames:
        table.add(frame)
        if table.ready:
            yield from table.expire(frame.ts)
    yield from table.close()


def _endpoints(frame: Frame) -> tuple[_Endpoint, _Endpoint]:
    """Source and destination endpoints of a frame.

    Only the first fragment of a datagram carries ports, so every fragment is
    keyed on addresses alone. Fragments therefore form their own flow rather
    than being dropped or guessed into the ported one.
    """
    if frame.fragmented:
        return (frame.src, 0), (frame.dst, 0)
    return (frame.src, frame.sport), (frame.dst, frame.dport)


def _canon(proto: int, src: _Endpoint, dst: _Endpoint) -> _Canon:
    """Direction-independent lookup key, so both halves find one flow."""
    return (proto, src, dst) if src <= dst else (proto, dst, src)


def _open_flow(frame: Frame, canon: _Canon, src: _Endpoint,
               dst: _Endpoint) -> tuple[Flow, bool]:
    """Start a flow, oriented from this frame alone.

    A bare SYN names its sender as the initiator and a SYN-ACK names its sender
    as the responder. Anything else leaves the first endpoint seen as the
    assumed initiator, to be corrected if a SYN turns up later.
    """
    oriented = bool(frame.flags & TCP_SYN)
    initiator, responder = (dst, src) if frame.is_synack else (src, dst)
    key = FlowKey(canon[0], initiator[0], initiator[1], responder[0], responder[1])
    return Flow(key=key, start=frame.ts, end=frame.ts), oriented


def _reorient(state: _State, frame: Frame, src: _Endpoint,
              dst: _Endpoint) -> None:
    """Correct an assumed orientation once a SYN reveals the real initiator."""
    if state.oriented or not frame.flags & TCP_SYN:
        return
    state.oriented = True
    initiator = dst if frame.is_synack else src
    if initiator != (state.flow.key.src, state.flow.key.sport):
        _swap(state)


def _swap(state: _State) -> None:
    flow, key = state.flow, state.flow.key
    flow.key = FlowKey(key.proto, key.dst, key.dport, key.src, key.sport)
    flow.packets_out, flow.packets_in = flow.packets_in, flow.packets_out
    flow.bytes_out, flow.bytes_in = flow.bytes_in, flow.bytes_out
    flow.payload_out, flow.payload_in = flow.payload_in, flow.payload_out
    state.fin_out, state.fin_in = state.fin_in, state.fin_out
    flow.responded = flow.packets_in > 0
