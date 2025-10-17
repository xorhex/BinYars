class Info:
    def __init__(self, is_temp_results: bool):
        self.temp_results = is_temp_results


class StateInfo:
    def __init__(self):
        self.state_info: dict[str, Info] = {}
        self.last_loaded_file_id = None

    def update(self, file_id: str, is_temp_results: bool):
        if file_id in self.state_info.keys():
            self.state_info[file_id].temp_results = is_temp_results
        else:
            self.state_info[file_id] = Info(is_temp_results)

    def get_last_update(self, file_id: str):
        if file_id in self.state_info.keys():
            return self.state_info[file_id].temp_results
        else:
            return False
