"""Trend chart: daily message volume (bars) with the DMARC pass rate (line) on top."""
from __future__ import annotations

from datetime import date

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from .style import GRADE_COLORS, T


class TrendChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.series: list[tuple[date, int, int]] = []
        self.empty_text = "No data for this selection."
        self.setMouseTracking(True)
        self.setMinimumHeight(260)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_series(self, series: list[tuple[date, int, int]]) -> None:
        self.series = series
        self.update()

    # geometry ---------------------------------------------------------------
    def _plot(self) -> QRectF:
        return QRectF(56, 18, max(self.width() - 56 - 56, 10), max(self.height() - 18 - 40, 10))

    def _x(self, i: int, plot: QRectF) -> float:
        n = len(self.series)
        step = plot.width() / max(n, 1)
        return plot.left() + step * (i + 0.5)

    # painting ---------------------------------------------------------------
    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor(T["card"]))
        plot = self._plot()
        small = QFont(self.font())
        small.setPointSizeF(8.5)
        p.setFont(small)
        muted, grid = QColor(T["muted"]), QColor(T["grid"])

        if not self.series or not any(m for _d, m, _p in self.series):
            p.setPen(muted)
            p.drawText(self.rect(), Qt.AlignCenter, self.empty_text)
            return

        max_msgs = max(m for _d, m, _p in self.series) or 1
        # grid + left axis (pass rate %)
        for pct in (0, 25, 50, 75, 100):
            y = plot.bottom() - plot.height() * pct / 100
            p.setPen(QPen(grid, 1))
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            p.setPen(muted)
            p.drawText(QRectF(0, y - 8, plot.left() - 8, 16), Qt.AlignRight | Qt.AlignVCenter,
                       f"{pct}%")
        # right axis (messages)
        for frac in (0, 0.5, 1):
            y = plot.bottom() - plot.height() * frac
            p.drawText(QRectF(plot.right() + 8, y - 8, 48, 16), Qt.AlignLeft | Qt.AlignVCenter,
                       f"{int(max_msgs * frac):,}")

        n = len(self.series)
        step = plot.width() / n
        bar_w = max(min(step * 0.6, 28), 1)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(T["chart_bar"]))
        for i, (_d, msgs, _ps) in enumerate(self.series):
            h = plot.height() * msgs / max_msgs
            p.drawRect(QRectF(self._x(i, plot) - bar_w / 2, plot.bottom() - h, bar_w, h))

        # pass-rate line (skips days with no mail)
        line = QPainterPath()
        started = False
        points = []
        for i, (_d, msgs, passed) in enumerate(self.series):
            if not msgs:
                started = False
                continue
            pt = QPointF(self._x(i, plot), plot.bottom() - plot.height() * passed / msgs)
            points.append((pt, passed / msgs))
            if started:
                line.lineTo(pt)
            else:
                line.moveTo(pt)
                started = True
        p.setPen(QPen(QColor(T["scan"]), 2.5))
        p.setBrush(Qt.NoBrush)
        p.drawPath(line)
        for pt, rate in points:
            color = GRADE_COLORS["A"] if rate >= 0.98 else GRADE_COLORS["C"] if rate >= 0.9 \
                else GRADE_COLORS["F"]
            p.setPen(QPen(QColor(T["card"]), 1.5))
            p.setBrush(QColor(color))
            p.drawEllipse(pt, 4, 4)

        # date labels
        p.setPen(muted)
        every = max(1, n // 10)
        for i, (d, _m, _ps) in enumerate(self.series):
            if i % every == 0 or i == n - 1:
                p.drawText(QRectF(self._x(i, plot) - 30, plot.bottom() + 6, 60, 16),
                           Qt.AlignHCenter | Qt.AlignTop, f"{d:%b %d}")
        # legend
        p.drawText(QRectF(plot.left(), plot.bottom() + 22, plot.width(), 16),
                   Qt.AlignLeft | Qt.AlignTop,
                   "Line: share of email passing DMARC (left axis).  Bars: messages per day "
                   "(right axis).")

    def mouseMoveEvent(self, event):
        if not self.series:
            return
        plot = self._plot()
        i = int((event.position().x() - plot.left()) / (plot.width() / len(self.series)))
        if 0 <= i < len(self.series):
            d, msgs, passed = self.series[i]
            rate = f"{passed / msgs * 100:.1f}% passed" if msgs else "no email reported"
            QToolTip.showText(event.globalPosition().toPoint(),
                              f"{d:%A, %B %d}\n{msgs:,} messages, {rate}", self)
