import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QPlainTextEdit,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QWidget,
)

from .charts import AssetMap
from .design import (
    Button,
    Card,
    Empty,
    Inspector,
    Metric,
    Search,
    Shell,
    Table,
    column,
    initialize,
    label,
    row,
    text_field,
)
from .reporting import read_report, write_html
from .runner import Runner

ACCENT = "#22D3EE"


class ScopeForge(Shell):
    def __init__(self):
        super().__init__("ScopeForge", "Attack Surface Workspace", ACCENT, "scope")
        self.runner = Runner("scopeforge")
        self.report = None
        self.assets = []
        self.metrics = []
        dashboard = self.add_page("Dashboard", "dashboard")
        scope = self.add_page("Alcance", "scope")
        targets = self.add_page("Objetivos", "target")
        inventory = self.add_page("Inventario", "servers")
        evidence = self.add_page("Evidencias", "evidence")
        reports = self.add_page("Reportes", "report")
        settings = self.add_page("Configuración", "settings")
        self.run_button = Button("Ejecutar inventario", self.scan, "play", ACCENT, True)
        self.header_actions.addWidget(
            Button("Cargar plan", self.load, "folder", ACCENT, quiet=True)
        )
        self.header_actions.addWidget(self.run_button)
        metric_row = QHBoxLayout()
        for title, glyph in [
            ("Objetivos observados", "target"),
            ("Respuestas HTTP", "servers"),
            ("Configuraciones a revisar", "shield"),
            ("Cambios detectados", "flows"),
        ]:
            card = Metric(title, glyph, ACCENT)
            metric_row.addWidget(card)
            self.metrics.append(card)
        dashboard.addLayout(metric_row)
        self.dashboard_content = QStackedWidget()
        dashboard.addWidget(self.dashboard_content, 1)
        self.dashboard_content.addWidget(
            Empty(
                "Tu superficie, con contexto",
                "Define el alcance autorizado y registra tus primeros objetivos.\nEl inventario aparecerá después de una observación real.",
                "network",
                ACCENT,
                "Configurar alcance",
                lambda: self.show_page("Alcance"),
            )
        )
        map_card = Card(
            "Relaciones observadas",
            "Las líneas conectan activos que comparten una IP. Se muestran hasta 18 activos; el inventario conserva el conjunto completo.",
        )
        self.map = AssetMap(ACCENT)
        self.map.selected.connect(self.inspect_asset)
        map_card.box.addWidget(self.map, 1)
        self.dashboard_content.addWidget(map_card)
        scope_card = Card(
            "Un alcance explícito",
            "Los dominios incluyen sus subdominios. Los CIDR delimitan direcciones; no se enumeran rangos automáticamente.",
        )
        form = QHBoxLayout()
        form.setSpacing(18)
        include, self.scope = text_field(
            "Raíces autorizadas", "Dominios o CIDR, uno por línea.", True
        )
        excluded, self.exclude = text_field(
            "Exclusiones", "Las exclusiones prevalecen sobre las reglas de inclusión.", True
        )
        self.scope.setMaximumHeight(260)
        self.exclude.setMaximumHeight(260)
        form.addWidget(include)
        form.addWidget(excluded)
        scope_card.box.addLayout(form)
        self.authorized = QCheckBox("Tengo autorización sobre los objetivos y el alcance definidos")
        scope_card.box.addWidget(self.authorized)
        scope_card.box.addLayout(
            row(
                Button("Validar sin solicitudes", self.check, "check", ACCENT),
                Button("Guardar plan", self.save, "download", ACCENT, quiet=True),
                None,
            )
        )
        scope.addWidget(scope_card)
        scope.addWidget(
            Card(
                "Qué comprueba el motor",
                "Cada destino se verifica antes de conectarse. Las direcciones resueltas se fijan para la conexión, las exclusiones también se aplican a IP y cada redirección vuelve a comprobarse.",
            )
        )
        scope.addStretch()
        target_card = Card(
            "Objetivos concretos",
            "Introduce hosts o URLs HTTP(S), uno por línea, sin contraseñas, query ni fragmentos.",
        )
        self.targets = QPlainTextEdit()
        self.targets.setPlaceholderText("Añade los objetivos autorizados que quieras observar")
        self.targets.setMinimumHeight(190)
        target_card.box.addWidget(self.targets)
        candidate_card = Card(
            "Candidatos de subdominio",
            "Prefijos propios que se combinarán con tus raíces de dominio. No hay listas precargadas ni consultas a servicios de terceros.",
        )
        self.candidates = QPlainTextEdit()
        self.candidates.setMaximumHeight(150)
        candidate_card.box.addWidget(self.candidates)
        targets.addWidget(target_card, 1)
        targets.addWidget(candidate_card)
        toolbar = QHBoxLayout()
        self.search = Search("Buscar dominio, IP o título…")
        self.state_filter = QComboBox()
        self.state_filter.addItems(["Todos los resultados", "complete", "blocked", "error"])
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.state_filter)
        inventory.addLayout(toolbar)
        splitter = QSplitter()
        self.inventory_table = Table(
            ["Objetivo", "Estado", "HTTP", "Direcciones", "TLS hasta", "Tiempo ms"], (1,)
        )
        self.inventory_table.setColumnWidth(0, 310)
        self.inventory_table.setColumnWidth(1, 135)
        self.inventory_table.setColumnWidth(3, 200)
        self.asset_inspector = Inspector("Detalle del objetivo")
        splitter.addWidget(self.inventory_table)
        splitter.addWidget(self.asset_inspector)
        splitter.setSizes([760, 340])
        self.inventory_table.selected.connect(self.asset_inspector.display)
        inventory.addWidget(splitter, 1)
        self.search.textChanged.connect(self.filter_assets)
        self.state_filter.currentIndexChanged.connect(self.filter_assets)
        evidence.addWidget(label("Hallazgos de configuración", "section"))
        evidence.addWidget(
            label("Los avisos no demuestran por sí solos una vulnerabilidad.", "muted")
        )
        self.evidence_table = Table(["Objetivo", "Regla", "Nivel", "Evidencia"], (2,))
        self.evidence_table.setColumnWidth(0, 300)
        self.evidence_table.setColumnWidth(1, 180)
        evidence.addWidget(self.evidence_table, 1)
        self.evidence_inspector = Inspector("Evidencia seleccionada")
        self.evidence_inspector.setMaximumHeight(230)
        self.evidence_table.selected.connect(self.evidence_inspector.display)
        evidence.addWidget(self.evidence_inspector)
        export = Card(
            "Reportes locales",
            "Los reportes JSON y HTML se guardan en la carpeta que elijas. HTML no requiere conexión ni carga recursos externos.",
        )
        export.box.addLayout(
            row(
                Button("Abrir reporte JSON", self.open_report, "folder", ACCENT),
                Button("Exportar HTML", self.export, "download", ACCENT),
                None,
            )
        )
        reports.addWidget(export)
        self.changes = Table(["Objetivo", "Cambio", "Campos modificados"])
        reports.addWidget(label("Comparación con una referencia", "section"))
        reports.addWidget(self.changes, 1)
        settings_card = Card(
            "Presupuesto de ejecución",
            "Los límites se aplican globalmente. La validación de TLS permanece activa.",
        )
        settings_row = QHBoxLayout()
        self.workers = self.spin(settings_row, "Concurrencia", 1, 16, 4)
        self.rate = self.spin(settings_row, "Pasos de red / segundo", 1, 50, 5)
        self.timeout = self.spin(settings_row, "Timeout por paso / segundos", 1, 30, 8)
        settings_card.box.addLayout(settings_row)
        self.http = QCheckBox("HTTP")
        self.https = QCheckBox("HTTPS")
        self.http.setChecked(True)
        self.https.setChecked(True)
        settings_card.box.addLayout(
            row(label("Esquemas para hosts sin URL", "muted"), self.https, self.http, None)
        )
        self.baseline_path = None
        self.baseline_label = label("Sin reporte de referencia", "mono", True)
        settings_card.box.addWidget(self.baseline_label)
        settings_card.box.addLayout(
            row(
                Button("Elegir referencia", self.baseline, "folder", ACCENT),
                Button("Reanudar checkpoint", self.resume, "clock", ACCENT),
                None,
            )
        )
        settings.addWidget(settings_card)
        settings.addStretch()
        self.shortcut("Ctrl+O", self.load)
        self.shortcut("Ctrl+S", self.save)
        self.shortcut("Ctrl+Return", self.scan)
        self.show_page("Dashboard")

    def spin(self, parent, title, minimum, maximum, value):
        holder = QWidget()
        box = column(holder, 7, 0)
        box.addWidget(label(title, "muted"))
        spin = QSpinBox()
        spin.setRange(minimum, maximum)
        spin.setValue(value)
        box.addWidget(spin)
        parent.addWidget(holder)
        return spin

    def lines(self, editor):
        return [line.strip() for line in editor.toPlainText().splitlines() if line.strip()]

    def config(self):
        return {
            "scope": self.lines(self.scope),
            "exclude": self.lines(self.exclude),
            "targets": self.lines(self.targets),
            "candidates": self.lines(self.candidates),
            "workers": self.workers.value(),
            "rate": self.rate.value(),
            "timeout_seconds": self.timeout.value(),
            "schemes": (["https"] if self.https.isChecked() else [])
            + (["http"] if self.http.isChecked() else []),
        }

    def save(self):
        path, _ = QFileDialog.getSaveFileName(self, "Guardar plan", "", "JSON (*.json)")
        if path:
            try:
                Path(path).write_text(
                    json.dumps(self.config(), ensure_ascii=False, indent=2), encoding="utf-8"
                )
                self.workspace_label.setText(Path(path).stem)
                self.notify("Plan guardado. No contiene credenciales.")
            except OSError as error:
                self.notify(str(error), True)

    def load(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar plan", "", "JSON (*.json)")
        if not path:
            return
        try:
            if Path(path).stat().st_size > 1024 * 1024:
                raise ValueError("El plan supera 1 MB.")
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            for name, editor in [
                ("scope", self.scope),
                ("exclude", self.exclude),
                ("targets", self.targets),
                ("candidates", self.candidates),
            ]:
                editor.setPlainText("\n".join(data.get(name, [])))
            self.workers.setValue(data.get("workers", 4))
            self.rate.setValue(data.get("rate", 5))
            self.timeout.setValue(data.get("timeout_seconds", 8))
            self.http.setChecked("http" in data.get("schemes", ["https", "http"]))
            self.https.setChecked("https" in data.get("schemes", ["https", "http"]))
            self.authorized.setChecked(False)
            self.workspace_label.setText(Path(path).stem)
            self.show_page("Alcance")
            self.notify("Plan cargado. Revisa el alcance antes de ejecutar.")
        except (OSError, ValueError, TypeError) as error:
            self.notify(str(error), True)

    def check(self):
        if self.busy:
            return
        config = self.config()

        def operation(note):
            with tempfile.TemporaryDirectory(prefix="scopeforge-check-") as folder:
                path = Path(folder) / "plan.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                self.runner.run(["--config", path, "--check"], note)
                return json.loads(self.runner.last_stdout)

        self.task(
            "Validando el plan sin actividad de red…",
            operation,
            lambda result: self.notify(
                f"Plan válido: {result['urls']} URLs concretas. No se enviaron solicitudes."
            ),
        )

    def baseline(self):
        path, _ = QFileDialog.getOpenFileName(self, "Reporte de referencia", "", "JSON (*.json)")
        if path:
            self.baseline_path = path
            self.baseline_label.setText(path)

    def resume(self):
        if self.busy:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Checkpoint de la misma configuración", "", "JSON (*.json)"
        )
        if path:
            self.scan(path)

    def scan(self, resume_path=None):
        if self.busy:
            return
        if not self.authorized.isChecked():
            self.show_page("Alcance")
            self.notify("Confirma autorización sobre el alcance antes de ejecutar.", True)
            return
        config = self.config()
        if not config["scope"] or not (config["targets"] or config["candidates"]):
            self.show_page("Alcance")
            self.notify("Define raíces autorizadas y objetivos concretos.", True)
            return
        folder = QFileDialog.getExistingDirectory(
            self, "Carpeta para el plan, checkpoint y reporte"
        )
        if not folder:
            return
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        plan = Path(folder) / (stamp + ".plan.json")
        state = Path(resume_path) if resume_path else Path(folder) / (stamp + ".state.json")
        output = Path(folder) / (stamp + ".report.json")
        baseline = self.baseline_path

        def operation(note):
            plan.write_text(json.dumps(config, indent=2), encoding="utf-8")
            args = ["--config", plan, "--state", state, "--out", output, "--authorized"]
            if resume_path:
                args.append("--resume")
            if baseline:
                args.extend(["--baseline", baseline])
            complete = self.runner.run(args, note)
            return (read_report(output) if output.exists() else None), complete

        self.task("Ejecutando inventario autorizado…", operation, self.finished, self.runner.cancel)

    def finished(self, value):
        report, complete = value
        if report:
            self.render(report)
        self.show_page("Inventario")
        self.notify(
            "Inventario finalizado."
            if complete
            else "Ejecución parcial. Conserva el checkpoint para reanudar."
        )

    def update_actions(self):
        self.run_button.setEnabled(not self.busy)

    def render(self, report):
        if report.get("tool") != "ScopeForge":
            raise ValueError("El reporte pertenece a otra herramienta.")
        self.report = report
        self.assets = report["assets"]
        findings = [
            (asset, finding) for asset in self.assets for finding in asset.get("findings", [])
        ]
        values = [
            len(self.assets),
            sum(a["outcome"] == "complete" for a in self.assets),
            len(findings),
            len(report.get("changes", [])),
        ]
        for card, value in zip(self.metrics, values):
            card.set(value, "Reporte completo" if report.get("complete") else "Reporte parcial")
        self.map.set_assets(self.assets)
        self.dashboard_content.setCurrentIndex(1 if self.assets else 0)
        self.filter_assets()
        self.evidence_table.fill(
            [
                (
                    [a["target"], f["rule"], f["severity"], f["evidence"]],
                    {"target": a["target"], **f},
                    {2: f["severity"]},
                )
                for a, f in findings
            ]
        )
        self.changes.fill(
            [
                ([c["target"], c["kind"], ", ".join(c["fields"])], c, {})
                for c in report.get("changes", [])
            ]
        )

    def filter_assets(self, *args):
        text = self.search.text().casefold()
        state = self.state_filter.currentText()
        rows = []
        for asset in self.assets:
            last = (asset.get("visits") or [{}])[-1]
            if (
                text not in json.dumps(asset, ensure_ascii=False).casefold()
                or self.state_filter.currentIndex() > 0
                and asset["outcome"] != state
            ):
                continue
            values = [
                asset["target"],
                asset["outcome"],
                last.get("status"),
                ", ".join(last.get("addresses", [])),
                (last.get("tls") or {}).get("not_after", "—"),
                last.get("duration_ms"),
            ]
            rows.append((values, asset, {1: asset["outcome"]}))
        self.inventory_table.fill(rows)

    def inspect_asset(self, asset):
        self.show_page("Inventario")
        self.asset_inspector.display(asset)

    def open_report(self):
        path, _ = QFileDialog.getOpenFileName(self, "Abrir reporte", "", "JSON (*.json)")
        if path:
            try:
                self.render(read_report(path))
                self.workspace_label.setText(Path(path).stem)
                self.show_page("Dashboard")
                self.notify("Reporte abierto sin enviar solicitudes.")
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.notify(str(error), True)

    def export(self):
        if not self.report:
            self.notify("Primero abre o genera un reporte.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar HTML local", "", "HTML (*.html)")
        if path:
            try:
                write_html(self.report, path)
                self.notify("Reporte HTML exportado sin recursos externos.")
            except OSError as error:
                self.notify(str(error), True)


def main():
    app = QApplication(sys.argv)
    initialize(app, ACCENT)
    window = ScopeForge()
    window.show()
    sys.exit(app.exec())
