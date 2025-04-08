class FileHandler:
    def __init__(self, filepath):
        self.path = filepath

    @staticmethod
    def normalize_path(path):
        #path = path.strip()
        if path.startswith('"'):
            path = path[1:]
        if path.endswith('"'):
            path = path[:-1]
        return path.replace('\\', '/')


