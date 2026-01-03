import sys
from PyQt6.QtWidgets import *
from PyQt6.QtCore import QTimer, QSize
from PyQt6.QtGui import QPixmap

TOTP_COUNT = [767550, 123456, 909876, 582923, 987456]
PROGRESS_BAR_TIME = 5


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TOTPGen")
        self.layout = QVBoxLayout()

        for totp_code in TOTP_COUNT:
            frame = self.create_frame(f"{totp_code}")
            self.layout.addWidget(frame)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, PROGRESS_BAR_TIME)

        self.layout.addWidget(self.progress_bar)
        self.create_timer()

        self.setLayout(self.layout)

        # TODO Window size should be a percentage of the display size/resolution.
        self.resize(300, 400)

    def create_frame(self, totp_code):
        totp = [123456, "Google", "youremail@domain.com"]

        frame = QFrame()
        frame_layout = QGridLayout()

        for i in range(len(totp)):
            font_size = 10
            item = totp[i]

            if isinstance(item, int):
                font_size = 18
                item = str(item)

            label = QLabel(item)
            label.setStyleSheet(f"font-size: {font_size}pt;")
            frame_layout.addWidget(label, i, 0)

        frame.setLayout(frame_layout)

        return frame

    def init_progress_bar(self):
        pass

    def create_timer(self):
        # Timer to update the progress bar
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.current_value = PROGRESS_BAR_TIME
        self.start_progress()

    def start_progress(self):
        self.current_value = PROGRESS_BAR_TIME
        self.progress_bar.setValue(self.current_value)
        self.timer.start(1000)  # Update every second

    def update_progress(self):
        if self.current_value > 0:
            self.current_value -= 1
            self.progress_bar.setValue(self.current_value)
        else:
            # Stop the timer when done
            print("CODES EXPIRED")
            self.timer.stop()
            print("Triggering refresh")
            self.start_progress()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
