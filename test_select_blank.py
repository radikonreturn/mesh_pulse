from textual.app import App, ComposeResult
from textual.widgets import Select


class SelectApp(App):
    def compose(self) -> ComposeResult:
        options = [("A", "a")]
        yield Select(options, value=Select.BLANK, allow_blank=True)


if __name__ == "__main__":
    app = SelectApp()
    app.run(headless=True)
