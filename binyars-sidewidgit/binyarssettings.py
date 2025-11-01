class BinYarSetting:
    def __init__(self, key: str, value: str | None):
        self.key = key
        self.value = value


class BinYarsSettings:
    def __init__(self, settings: list[dict[str, str | None]]):
        self.settings: list[BinYarSetting] = []
        for setting in settings:
            for k, v in setting.items():
                self.settings.append(BinYarSetting(k, v))

    def DoNotRenderAllStringMatches(self) -> bool:
        return any(s.key == "!sr" and s.value is None for s in self.settings)

    def DoNotRenderStringMatches(self, value: str) -> bool:
        return any(s.key == "!sr" and s.value == value for s in self.settings)
