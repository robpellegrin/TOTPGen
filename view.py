from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QVBoxLayout,
    QProgressBar,
    QFrame,
    QGridLayout,
    QLabel,
    QWidget,
)


class MainWindow(QWidget):
    PROGRESS_BAR_TIME = 30  # Seconds

    def __init__(self, totp_list):
        super().__init__()
        self.setWindowTitle("TOTPGen")
        self.layout = QVBoxLayout()

        self.current_value = 30

        self.totp_labels = []
        self.totp_objects = []

        for totp in totp_list:
            frame = self.create_frame(totp)
            self.layout.addWidget(frame)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, self.PROGRESS_BAR_TIME)

        self.layout.addWidget(self.progress_bar)
        self.create_timer()

        self.setLayout(self.layout)

        # TODO Window size should be a percentage of the display size/resolution.
        self.resize(300, 400)

    def create_frame(self, totp):
        frame = QFrame()
        frame_layout = QGridLayout()

        totp_label = QLabel(totp.get_totp())
        totp_label.setStyleSheet("font-size: 16pt;")

        name_label = QLabel(totp.name)
        name_label.setStyleSheet("font-size: 9pt;")

        account_label = QLabel(totp.account)
        account_label.setStyleSheet("font-size: 9pt;")

        frame_layout.addWidget(totp_label, 0, 0)
        frame_layout.addWidget(name_label, 1, 0)
        frame_layout.addWidget(account_label, 2, 0)

        frame.setLayout(frame_layout)

        # Store the TOTP object and the label for later updates
        self.totp_labels.append(totp_label)
        self.totp_objects.append(totp)

        return frame

    def create_timer(self):
        # Timer to update the progress bar
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)

        self.start_progress()

    def start_progress(self):
        self.current_value = self.PROGRESS_BAR_TIME
        self.progress_bar.setValue(self.current_value)
        self.timer.start(1000)  # Update every second

    def update_progress(self):
        if self.current_value > 0:
            self.current_value -= 1
            self.progress_bar.setValue(self.current_value)
        else:
            self.timer.stop()
            self.refresh_totp_codes()
            self.start_progress()

    def refresh_totp_codes(self):
        for i, totp_label in enumerate(self.totp_labels):
            # Regenerate TOTP for each corresponding TOTP object
            new_totp = self.totp_objects[i].get_totp()
            totp_label.setText(new_totp)
