from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox, QTextEdit, QHBoxLayout, QLineEdit, QProgressBar
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
import sys
import json
import re
import os

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

class AwarenessApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IT-Sicherheits-Simulator")
        self.resize(1200, 800)
        self.setStyleSheet("background-color: #F5F5DC; color: black;")

        try:
            self.scenarios = self.load_json_data(resource_path("data/phishing.json"))
        except (FileNotFoundError, json.JSONDecodeError):
            QMessageBox.critical(self, "Fehler", "phishing.json konnte nicht geladen werden oder ist ungültig.")
            self.scenarios = []

        try:
            self.urls = self.load_json_data(resource_path("data/urls.json"))
        except (FileNotFoundError, json.JSONDecodeError):
            QMessageBox.critical(self, "Fehler", "urls.json konnte nicht geladen werden oder ist ungültig.")
            self.urls = []

        self.current = 0
        self.score = 0
        self.results = []

        layout = QVBoxLayout()
        self.setLayout(layout)
        self.main_menu()

    def load_json_data(self, filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def clear_layout(self):
        layout = self.layout()
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def main_menu(self):
        self.clear_layout()
        layout = self.layout()

        title = QLabel("Willkommen zum IT-Sicherheits-Simulator")
        title.setFont(QFont("Arial", 28))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        btn_style = (
            "QPushButton { background-color: #4CAF50; color: white; padding: 25px; border-radius: 8px; font-size: 22px; }"
            "QPushButton:hover { background-color: #45a049; }"
        )

        phishing_btn = QPushButton("📧 Phishing-Simulation")
        phishing_btn.setStyleSheet(btn_style)
        phishing_btn.clicked.connect(self.start_phishing)
        layout.addWidget(phishing_btn)

        password_btn = QPushButton("🔐 Passwort-Stärke-Test")
        password_btn.setStyleSheet(btn_style)
        password_btn.clicked.connect(self.start_password_test)
        layout.addWidget(password_btn)

        url_btn = QPushButton("🌐 Sichere-URL-Erkennung")
        url_btn.setStyleSheet(btn_style)
        url_btn.clicked.connect(self.start_url_check)
        layout.addWidget(url_btn)

    def start_password_test(self):
        self.clear_layout()
        layout = self.layout()

        header = QLabel("🔐 Passwort-Stärke-Test")
        header.setFont(QFont("Arial", 24))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        instruction = QLabel("Bitte geben Sie ein Passwort ein:")
        instruction.setFont(QFont("Arial", 18))
        instruction.setAlignment(Qt.AlignCenter)
        layout.addWidget(instruction)

        self.password_input = QLineEdit()
        self.password_input.setFont(QFont("Arial", 16))
        self.password_input.setStyleSheet("background-color: white; color: black; padding: 10px;")
        self.password_input.setEchoMode(QLineEdit.Normal)
        self.password_input.textChanged.connect(self.evaluate_password)
        layout.addWidget(self.password_input)

        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setFixedHeight(50)
        layout.addWidget(self.strength_bar)

        self.strength_label = QLabel("")
        self.strength_label.setFont(QFont("Arial", 18))
        self.strength_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.strength_label)

        back_btn = QPushButton("Zurück zum Menü")
        back_btn.setStyleSheet("background-color: #2196F3; color: white; padding: 15px; font-size: 18px;")
        back_btn.clicked.connect(self.main_menu)
        layout.addWidget(back_btn)

    def evaluate_password(self):
        password = self.password_input.text()
        score = 0

        if len(password) >= 8:
            score += 25
        if re.search(r"[A-Z]", password):
            score += 25
        if re.search(r"[0-9]", password):
            score += 25
        if re.search(r"[^a-zA-Z0-9]", password):
            score += 25

        self.strength_bar.setValue(score)

        if score < 50:
            self.strength_label.setText("Schwach: Verwenden Sie mindestens 8 Zeichen, Großbuchstaben, Zahlen und Sonderzeichen.")
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: red; }")
        elif score < 75:
            self.strength_label.setText("Mittel: Gut, aber könnte sicherer sein.")
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: orange; }")
        else:
            self.strength_label.setText("Stark: Gutes sicheres Passwort.")
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: green; }")

    def start_phishing(self):
        if not self.scenarios:
            QMessageBox.warning(self, "Fehler", "Keine Phishing-Szenarien verfügbar.")
            return
        self.current = 0
        self.score = 0
        self.results = []
        self.show_phishing_scenario()

    def show_phishing_scenario(self):
        if self.current >= len(self.scenarios):
            result_text = "Ergebnisse:\n"
            for idx, res in enumerate(self.results, 1):
                result_text += f"{idx}. {res}\n"
            QMessageBox.information(self, "Auswertung", result_text)
            self.main_menu()
            return

        scenario = self.scenarios[self.current]
        self.clear_layout()
        layout = self.layout()

        header = QLabel(f"E-Mail {self.current + 1} von {len(self.scenarios)}")
        header.setFont(QFont("Arial", 20))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        email_box = QTextEdit()
        email_box.setReadOnly(True)
        email_box.setStyleSheet("background-color: white; color: black; font-size: 16px;")
        email_content = f"Von: {scenario.get('from', '')}\nBetreff: {scenario.get('subject', '')}\n\n{scenario.get('body', '')}"
        email_box.setText(email_content)
        layout.addWidget(email_box)

        btn_layout = QHBoxLayout()
        legit_btn = QPushButton("✅ Legitim")
        legit_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 15px; font-size: 18px;")
        legit_btn.clicked.connect(lambda: self.check_answer("sicher", self.scenarios, self.show_phishing_scenario))

        phishing_btn = QPushButton("🚨 Phishing")
        phishing_btn.setStyleSheet("background-color: #f44336; color: white; padding: 15px; font-size: 18px;")
        phishing_btn.clicked.connect(lambda: self.check_answer("phishing", self.scenarios, self.show_phishing_scenario))

        btn_layout.addWidget(legit_btn)
        btn_layout.addWidget(phishing_btn)
        layout.addLayout(btn_layout)

    def start_url_check(self):
        if not self.urls:
            QMessageBox.warning(self, "Fehler", "Keine URL-Szenarien verfügbar.")
            return
        self.current = 0
        self.score = 0
        self.results = []
        self.show_url_scenario()

    def show_url_scenario(self):
        if self.current >= len(self.urls):
            result_text = "Ergebnisse:\n"
            for idx, res in enumerate(self.results, 1):
                result_text += f"{idx}. {res}\n"
            QMessageBox.information(self, "Auswertung", result_text)
            self.main_menu()
            return

        url = self.urls[self.current]
        self.clear_layout()
        layout = self.layout()

        header = QLabel(f"URL {self.current + 1} von {len(self.urls)}")
        header.setFont(QFont("Arial", 20))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        url_box = QTextEdit()
        url_box.setReadOnly(True)
        url_box.setStyleSheet("background-color: white; color: black; font-size: 16px;")
        url_box.setText(url.get('url', ''))
        layout.addWidget(url_box)

        btn_layout = QHBoxLayout()
        legit_btn = QPushButton("✅ Sicher")
        legit_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 15px; font-size: 18px;")
        legit_btn.clicked.connect(lambda: self.check_answer("sicher", self.urls, self.show_url_scenario))

        phishing_btn = QPushButton("🚨 Phishing")
        phishing_btn.setStyleSheet("background-color: #f44336; color: white; padding: 15px; font-size: 18px;")
        phishing_btn.clicked.connect(lambda: self.check_answer("phishing", self.urls, self.show_url_scenario))

        btn_layout.addWidget(legit_btn)
        btn_layout.addWidget(phishing_btn)
        layout.addLayout(btn_layout)

    def check_answer(self, answer, dataset, callback):
        scenario = dataset[self.current]
        correct = scenario.get('correct_answer', '')
        explanation = scenario.get('explanation', 'Keine Erklärung vorhanden.')

        if answer == correct:
            self.score += 1
            self.results.append(f"✅ Richtig: {explanation}")
        else:
            self.results.append(f"❌ Falsch: {explanation}")

        self.current += 1
        callback()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AwarenessApp()
    window.show()
    sys.exit(app.exec())
