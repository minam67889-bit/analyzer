"""Adversary Lab desktop application.

Every control is bound to a controller method; there are no decorative buttons. The UI is
a thin view over the same orchestrator used by the CLI, so behaviour is identical across
interfaces. PySide6 is an optional dependency: importing this module without it raises a
clear error.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

try:
    from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QUrl, Signal, Slot
    from PySide6.QtGui import QAction, QDesktopServices
    from PySide6.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QComboBox,
        QFormLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QMainWindow,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover - depends on environment
    raise ImportError(
        "The desktop UI could not be loaded. If PySide6 is missing, install it with "
        "`pip install -e .[ui]`. On Linux hosts the Qt libraries also need system "
        "packages (libGL, libEGL, libxkbcommon, libdbus, libfontconfig); without them "
        "the import fails even though PySide6 is installed. Underlying error: "
        f"{exc}"
    ) from exc

from .. import __version__
from ..adversary.actions import FakeActionRunner, ServiceBackedActionRunner
from ..adversary.orchestrator import Orchestrator
from ..config.loader import load_config
from ..config.schema import default_config
from ..core.bus import EventBus, RecordingSink
from ..core.store import Database
from ..platform.adb import AdbClient, AndroidTelemetry
from ..platform.windows import WindowsCapabilityProbe
from ..reporting.report import ReportGenerator
from ..tests.catalog import build_default_registry


class EventTableModel(QAbstractTableModel):
    """Thread-safe-ish append-only event table (UI updates are marshalled to the GUI thread)."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._rows: list[dict[str, Any]] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 7

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return ["Time", "Category", "Source", "Severity", "Summary", "Source Addr", "Dst Addr"][section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole or not index.isValid():
            return None
        row = self._rows[index.row()]
        return [
            row.get("timestamp", "")[11:23], row.get("category"), row.get("source"),
            row.get("severity"), row.get("summary"), row.get("src_addr"), row.get("dst_addr"),
        ][index.column()]

    def append(self, event) -> None:
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append(event.to_dict())
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()


class AppController(QObject):
    status_changed = Signal(str)
    events_appended = Signal(object)
    coverage_updated = Signal(list)
    results_updated = Signal(list)

    def __init__(self, config_path: str | None = None, evidence_root: str = "evidence",
                 db_path: str = "adversarylab.db", dry_run: bool = True) -> None:
        super().__init__()
        self.config_path = config_path
        self.evidence_root = evidence_root
        self.dry_run = dry_run
        self.db = Database(db_path)
        self.bus = EventBus()
        self.registry = build_default_registry()
        self.capabilities = WindowsCapabilityProbe().run()
        self.bus.subscribe(self._on_event)
        self.recording = RecordingSink()
        self.bus.subscribe(self.recording)
        config = load_config(config_path) if config_path else default_config()
        runner = FakeActionRunner() if dry_run else ServiceBackedActionRunner(bus=self.bus, session_id="")
        self.orchestrator = Orchestrator(
            config=config,
            registry=self.registry,
            capabilities=self.capabilities,
            bus=self.bus,
            db=self.db,
            evidence_root=evidence_root,
            action_runner=runner,
            device=None,
            lab=None,
            capture=None,
        )
        self._device_client: AdbClient | None = None

    # ------------------------------------------------------------------
    def _on_event(self, event) -> None:
        self.events_appended.emit(event)

    # ------------------------------------------------------------------
    def capability_summary(self) -> dict[str, int]:
        available = sum(1 for report in self.capabilities if report.available)
        return {"available": available, "total": len(list(self.capabilities))}

    def state_text(self) -> str:
        return self.orchestrator.state.state.value

    def create_session(self) -> str:
        return self.orchestrator.create_session()

    def prepare(self) -> dict:
        return self.orchestrator.prepare().to_dict()

    def plan(self) -> dict:
        return self.orchestrator.plan().to_dict()

    def run_test(self, test_id: str) -> dict:
        return self.orchestrator.run_test(test_id, params={"ui": True}).to_dict()

    def run_scenario(self, scenario_id: str) -> list[dict]:
        scenario = self.orchestrator.scenarios.get(scenario_id)
        if scenario is None:
            raise ValueError(f"unknown scenario {scenario_id!r}")
        return [r.to_dict() for r in self.orchestrator.run_scenario(scenario)]

    def run_campaign(self, campaign_id: str) -> dict:
        from ..adversary.campaigns import CampaignLibrary

        campaign = CampaignLibrary().get(campaign_id)
        if campaign is None:
            raise ValueError(f"unknown campaign {campaign_id!r}")
        return self.orchestrator.run_campaign(campaign).to_dict()

    def campaigns(self) -> list[dict]:
        from ..adversary.campaigns import CampaignLibrary

        return CampaignLibrary().to_dict()

    def run_assessment(self) -> dict:
        return self.orchestrator.run_assessment().to_dict()

    def pause(self) -> None:
        self.orchestrator.pause()

    def resume(self) -> None:
        self.orchestrator.resume()

    def stop(self) -> None:
        self.orchestrator.stop()

    def emergency_stop(self) -> None:
        self.orchestrator.emergency_stop()

    def generate_report(self, output_dir: str) -> dict[str, str]:
        result = self.orchestrator._last_result
        if result is None:
            raise ValueError("no assessment has completed")
        evidence = [r.to_dict() for r in self.orchestrator.evidence.records] if self.orchestrator.evidence else []
        paths = ReportGenerator(result).write(output_dir, evidence_records=evidence)
        from ..reporting.extra_reports import ReportBundle

        reveal = bool(
            self.orchestrator.config.tests.to_dict().get("reveal_cookie_values", False)
        )
        bundle = ReportBundle(result, reveal_cookie_values=reveal).write(
            Path(output_dir) / "mandatory"
        )
        paths.update({f"mandatory/{key}": value for key, value in bundle.items()})
        return {k: str(v) for k, v in paths.items()}

    def device_info(self) -> dict:
        if self._device_client is None:
            self._device_client = AdbClient()
        telemetry = AndroidTelemetry(self._device_client)
        return telemetry.device_info()

    def vpn_state(self) -> dict:
        if self._device_client is None:
            self._device_client = AdbClient()
        return AndroidTelemetry(self._device_client).vpn_state()

    def test_catalog(self) -> list[dict]:
        return [s.to_dict() for s in self.registry.specs()]

    def profiles(self) -> list[dict]:
        return self.orchestrator.profiles.to_dict()

    def scenarios(self) -> list[dict]:
        return self.orchestrator.scenarios.to_dict()

    def evidence_records(self) -> list[dict]:
        if self.orchestrator.evidence is None:
            return []
        return [r.to_dict() for r in self.orchestrator.evidence.records]


class DashboardPage(QWidget):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        layout = QVBoxLayout(self)
        self.status = QLabel("State: idle")
        self.session = QLabel("Session: none")
        self.capabilities = QLabel("Capabilities: -")
        layout.addWidget(self.status)
        layout.addWidget(self.session)
        layout.addWidget(self.capabilities)
        buttons = QHBoxLayout()
        self.refresh = QPushButton("Refresh")
        self.prepare_btn = QPushButton("Prepare Laboratory")
        self.run_btn = QPushButton("Run Full Assessment")
        self.emergency = QPushButton("EMERGENCY STOP")
        self.emergency.setStyleSheet("background:#b91c1c;color:white;font-weight:bold;")
        for button in (self.refresh, self.prepare_btn, self.run_btn, self.emergency):
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(QLabel("Controller log"))
        layout.addWidget(self.log)
        self.refresh.clicked.connect(self.refresh_status)
        self.prepare_btn.clicked.connect(self.prepare)
        self.run_btn.clicked.connect(self.run_assessment)
        self.emergency.clicked.connect(self.emergency)
        controller.status_changed.connect(self.status.setText)

    def refresh_status(self) -> None:
        summary = self.controller.capability_summary()
        self.status.setText(f"State: {self.controller.state_text()}")
        self.capabilities.setText(
            f"Capabilities available: {summary['available']}/{summary['total']}"
        )
        try:
            self.session.setText(f"Session: {self.controller.create_session()}")
        except Exception as exc:
            self.session.setText(f"Session: error: {exc}")

    def prepare(self) -> None:
        try:
            report = self.controller.prepare()
            self.log.appendPlainText(f"preparation ok={report['ok']} problems={report['problems']}")
        except Exception as exc:
            QMessageBox.critical(self, "Preparation failed", str(exc))

    def run_assessment(self) -> None:
        try:
            result = self.controller.run_assessment()
            self.log.appendPlainText(f"assessment status={result['status']} results={len(result['results'])}")
        except Exception as exc:
            QMessageBox.critical(self, "Assessment failed", str(exc))

    def emergency(self) -> None:
        self.controller.emergency_stop()
        self.log.appendPlainText("EMERGENCY STOP engaged")


class InfrastructurePage(QWidget):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.backend = QLineEdit("auto")
        self.ssid = QLineEdit(controller.orchestrator.config.infrastructure.ssid)
        self.gateway = QLineEdit(controller.orchestrator.config.infrastructure.ipv4_gateway)
        self.dns = QLineEdit("10.10.0.1")
        form.addRow("Backend", self.backend)
        form.addRow("SSID", self.ssid)
        form.addRow("IPv4 gateway", self.gateway)
        form.addRow("DNS", self.dns)
        layout.addLayout(form)
        self.start = QPushButton("Start Infrastructure")
        self.stop = QPushButton("Stop Infrastructure")
        layout.addWidget(self.start)
        layout.addWidget(self.stop)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        self.start.clicked.connect(self.start_infra)
        self.stop.clicked.connect(self.stop_infra)

    def start_infra(self) -> None:
        try:
            report = self.controller.prepare()
            self.output.appendPlainText(f"infrastructure: {report['infrastructure']}")
        except Exception as exc:
            QMessageBox.critical(self, "Start failed", str(exc))

    def stop_infra(self) -> None:
        self.controller.stop()
        self.output.appendPlainText("infrastructure stop requested")


class AdversaryLabPage(QWidget):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(QLabel("Adversary profiles"))
        self.profiles_list = QListWidget()
        left_layout.addWidget(self.profiles_list)
        left_layout.addWidget(QLabel("Scenarios"))
        self.scenarios_list = QListWidget()
        left_layout.addWidget(self.scenarios_list)
        self.run_scenario = QPushButton("Run Selected Scenario")
        left_layout.addWidget(self.run_scenario)
        left_layout.addWidget(QLabel("Multi-stage campaigns"))
        self.campaigns_list = QListWidget()
        left_layout.addWidget(self.campaigns_list)
        self.run_campaign = QPushButton("Run Selected Campaign")
        left_layout.addWidget(self.run_campaign)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(QLabel("Test catalog"))
        self.tests_table = QTableWidget(0, 4)
        self.tests_table.setHorizontalHeaderLabels(["ID", "Category", "Name", "Capabilities"])
        self.tests_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        right_layout.addWidget(self.tests_table)
        self.run_test = QPushButton("Run Selected Test")
        right_layout.addWidget(self.run_test)
        splitter.addWidget(right)
        layout = QVBoxLayout(self)
        layout.addWidget(splitter)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        self.refresh()
        self.run_scenario.clicked.connect(self.run_selected_scenario)
        self.run_campaign.clicked.connect(self.run_selected_campaign)
        self.run_test.clicked.connect(self.run_selected_test)

    def refresh(self) -> None:
        self.profiles_list.clear()
        for profile in self.controller.profiles():
            self.profiles_list.addItem(f"{profile['id']} — {profile['name']}")
        self.scenarios_list.clear()
        for scenario in self.controller.scenarios():
            self.scenarios_list.addItem(f"{scenario['id']} — {scenario['name']}")
        self.campaigns_list.clear()
        for campaign in self.controller.campaigns():
            self.campaigns_list.addItem(f"{campaign['id']} — {campaign['name']}")
        self.tests_table.setRowCount(0)
        for spec in self.controller.test_catalog():
            row = self.tests_table.rowCount()
            self.tests_table.insertRow(row)
            self.tests_table.setItem(row, 0, QTableWidgetItem(spec["id"]))
            self.tests_table.setItem(row, 1, QTableWidgetItem(spec["category"]))
            self.tests_table.setItem(row, 2, QTableWidgetItem(spec["name"]))
            self.tests_table.setItem(row, 3, QTableWidgetItem(",".join(spec["required_capabilities"])))

    def run_selected_scenario(self) -> None:
        item = self.scenarios_list.currentItem()
        if not item:
            QMessageBox.information(self, "No selection", "Select a scenario first.")
            return
        scenario_id = item.text().split(" — ")[0]
        try:
            results = self.controller.run_scenario(scenario_id)
            self.output.appendPlainText(f"scenario {scenario_id}: {len(results)} results")
            for result in results:
                self.output.appendPlainText(
                    f"  {result['test_id']} -> {result['verdict']} ({result['confidence']})"
                )
        except Exception as exc:
            QMessageBox.critical(self, "Scenario failed", str(exc))

    def run_selected_campaign(self) -> None:
        item = self.campaigns_list.currentItem()
        if not item:
            QMessageBox.information(self, "No selection", "Select a campaign first.")
            return
        campaign_id = item.text().split(" — ")[0]
        try:
            run = self.controller.run_campaign(campaign_id)
            self.output.appendPlainText(
                f"campaign {campaign_id}: {run['status']} objective={run['objective_reached']}"
            )
            self.output.appendPlainText(f"  {run['explanation']}")
            for stage in run["stages"]:
                verdict = (stage.get("result") or {}).get("verdict", "-")
                self.output.appendPlainText(
                    f"  stage {stage['stage']['name']}: feasible={stage['feasible']} verdict={verdict}"
                )
        except Exception as exc:
            QMessageBox.critical(self, "Campaign failed", str(exc))

    def run_selected_test(self) -> None:
        row = self.tests_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "No selection", "Select a test first.")
            return
        test_id = self.tests_table.item(row, 0).text()
        try:
            result = self.controller.run_test(test_id)
            self.output.appendPlainText(f"{test_id} -> {result['verdict']} ({result['confidence']})")
        except Exception as exc:
            QMessageBox.critical(self, "Test failed", str(exc))


class DeviceMonitorPage(QWidget):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        layout = QVBoxLayout(self)
        buttons = QHBoxLayout()
        self.refresh = QPushButton("Refresh Device")
        self.vpn_btn = QPushButton("Read VPN State")
        buttons.addWidget(self.refresh)
        buttons.addWidget(self.vpn_btn)
        layout.addLayout(buttons)
        self.info = QTableWidget(0, 2)
        self.info.setHorizontalHeaderLabels(["Property", "Value"])
        layout.addWidget(QLabel("Device information"))
        layout.addWidget(self.info)
        self.vpn = QPlainTextEdit()
        self.vpn.setReadOnly(True)
        layout.addWidget(QLabel("VPN / tunnel state"))
        layout.addWidget(self.vpn)
        self.refresh.clicked.connect(self.load_info)
        self.vpn_btn.clicked.connect(self.load_vpn)

    def load_info(self) -> None:
        try:
            info = self.controller.device_info()
        except Exception as exc:
            QMessageBox.critical(self, "Device error", str(exc))
            return
        self.info.setRowCount(0)
        for key, value in info.items():
            row = self.info.rowCount()
            self.info.insertRow(row)
            self.info.setItem(row, 0, QTableWidgetItem(key))
            self.info.setItem(row, 1, QTableWidgetItem(str(value)))

    def load_vpn(self) -> None:
        try:
            self.vpn.setPlainText(json_dumps(self.controller.vpn_state()))
        except Exception as exc:
            QMessageBox.critical(self, "Device error", str(exc))


class LiveAnalysisPage(QWidget):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        self.model = EventTableModel(self)
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self.category = QComboBox()
        self.category.addItems(["all", "dns", "dhcp", "arp", "ipv6_neighbor", "tls", "http",
                                "quic", "connection", "vpn_state", "route_state", "firewall"])
        self.pause = QPushButton("Pause Live View")
        self.clear = QPushButton("Clear")
        self.search = QLineEdit()
        self.search.setPlaceholderText("filter text")
        controls.addWidget(QLabel("Category"))
        controls.addWidget(self.category)
        controls.addWidget(self.search)
        controls.addWidget(self.pause)
        controls.addWidget(self.clear)
        layout.addLayout(controls)
        from PySide6.QtWidgets import QTableView

        self.table = QTableView()
        self.table.setModel(self.model)
        layout.addWidget(self.table)
        controller.events_appended.connect(self.on_event)
        self.pause.clicked.connect(self.toggle_pause)
        self.clear.clicked.connect(self.model.clear)
        self.category.currentIndexChanged.connect(self.apply_filter)
        self._paused = False

    @Slot(object)
    def on_event(self, event) -> None:
        if self._paused:
            return
        if self.category.currentText() != "all" and event.category.value != self.category.currentText():
            return
        text = self.search.text().strip().lower()
        if text and text not in event.summary.lower():
            return
        self.model.append(event)

    def toggle_pause(self) -> None:
        self._paused = not self._paused
        self.pause.setText("Resume Live View" if self._paused else "Pause Live View")

    def apply_filter(self) -> None:
        self.model.clear()
        category = self.category.currentText()
        for event in self.controller.recording.events:
            if category != "all" and event.category.value != category:
                continue
            self.model.append(event)


class AssessmentPage(QWidget):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        layout = QVBoxLayout(self)
        buttons = QHBoxLayout()
        self.plan_btn = QPushButton("Build Plan")
        self.run_btn = QPushButton("Run Assessment")
        buttons.addWidget(self.plan_btn)
        buttons.addWidget(self.run_btn)
        layout.addLayout(buttons)
        self.coverage = QTableWidget(0, 5)
        self.coverage.setHorizontalHeaderLabels(["Test", "Category", "Status", "Verdict", "Reason"])
        layout.addWidget(QLabel("Coverage matrix"))
        layout.addWidget(self.coverage)
        self.results = QTableWidget(0, 4)
        self.results.setHorizontalHeaderLabels(["Test", "Verdict", "Confidence", "Block cause"])
        layout.addWidget(QLabel("Results"))
        layout.addWidget(self.results)
        self.plan_btn.clicked.connect(self.build_plan)
        self.run_btn.clicked.connect(self.run_assessment)

    def build_plan(self) -> None:
        try:
            plan = self.controller.plan()
        except Exception as exc:
            QMessageBox.critical(self, "Planning failed", str(exc))
            return
        self.coverage.setRowCount(0)
        for row in plan["coverage"]:
            r = self.coverage.rowCount()
            self.coverage.insertRow(r)
            self.coverage.setItem(r, 0, QTableWidgetItem(row["test_id"]))
            self.coverage.setItem(r, 1, QTableWidgetItem(row["category"]))
            self.coverage.setItem(r, 2, QTableWidgetItem(row["status"]))
            self.coverage.setItem(r, 3, QTableWidgetItem(row.get("verdict", "")))
            self.coverage.setItem(r, 4, QTableWidgetItem(row.get("reason", "")))

    def run_assessment(self) -> None:
        try:
            result = self.controller.run_assessment()
        except Exception as exc:
            QMessageBox.critical(self, "Assessment failed", str(exc))
            return
        self.results.setRowCount(0)
        for row in result["results"]:
            r = self.results.rowCount()
            self.results.insertRow(r)
            self.results.setItem(r, 0, QTableWidgetItem(row["test_id"]))
            self.results.setItem(r, 1, QTableWidgetItem(row["verdict"]))
            self.results.setItem(r, 2, QTableWidgetItem(row["confidence"]))
            self.results.setItem(r, 3, QTableWidgetItem(row["block_cause"]))


class ReportsPage(QWidget):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.output = QLineEdit("report")
        form.addRow("Output directory", self.output)
        layout.addLayout(form)
        self.generate = QPushButton("Generate Report")
        self.open_btn = QPushButton("Open HTML Report")
        layout.addWidget(self.generate)
        layout.addWidget(self.open_btn)
        self.output_path = QLineEdit()
        self.output_path.setReadOnly(True)
        layout.addWidget(self.output_path)
        self.generate.clicked.connect(self.generate_report)
        self.open_btn.clicked.connect(self.open_report)

    def generate_report(self) -> None:
        try:
            paths = self.controller.generate_report(self.output.text())
        except Exception as exc:
            QMessageBox.critical(self, "Report failed", str(exc))
            return
        self.output_path.setText(paths["html"])

    def open_report(self) -> None:
        path = self.output_path.text()
        if not path:
            QMessageBox.information(self, "No report", "Generate a report first.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))


class LabWindow(QMainWindow):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        self.setWindowTitle(f"Adversary Lab {__version__}")
        self.resize(1280, 800)
        tabs = QTabWidget()
        tabs.addTab(DashboardPage(controller), "Dashboard")
        tabs.addTab(InfrastructurePage(controller), "Infrastructure")
        tabs.addTab(AdversaryLabPage(controller), "Adversary Lab")
        tabs.addTab(DeviceMonitorPage(controller), "Device Monitor")
        tabs.addTab(LiveAnalysisPage(controller), "Live Analysis")
        tabs.addTab(AssessmentPage(controller), "Assessment")
        tabs.addTab(ReportsPage(controller), "Reports")
        self.setCentralWidget(tabs)
        self._build_menu()

    def _build_menu(self) -> None:
        menu = self.menuBar().addMenu("Laboratory")
        refresh = QAction("Refresh Status", self)
        refresh.triggered.connect(self._refresh_status)
        emergency = QAction("Emergency Stop", self)
        emergency.triggered.connect(self.controller.emergency_stop)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        menu.addAction(refresh)
        menu.addAction(emergency)
        menu.addSeparator()
        menu.addAction(quit_action)

    def _refresh_status(self) -> None:
        summary = self.controller.capability_summary()
        self.statusBar().showMessage(
            f"state={self.controller.state_text()} capabilities={summary['available']}/{summary['total']}"
        )


def json_dumps(payload: Any) -> str:
    import json

    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def run_app(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    config_path = None
    if "--config" in args:
        index = args.index("--config")
        config_path = args[index + 1]
        del args[index : index + 2]
    dry_run = "--live" not in args
    if "--live" in args:
        args.remove("--live")
    app = QApplication(args)
    controller = AppController(config_path=config_path, dry_run=dry_run)
    window = LabWindow(controller)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(run_app())
