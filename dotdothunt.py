#!/usr/bin/env python3
import asyncio
import re
import tkinter as tk
from tkinter import ttk, scrolledtext, font
import yarl

from dotdothunt.generators.words_generator import Generator
from dotdothunt.engines.http_engine import HTTPEngine

class DotDotHuntGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DotDotHunt - Path Traversal Tool")
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.hits_found = False  # Flag to track if any hits are found

        # Main frame aligned at the top
        main_frame = tk.Frame(root)
        main_frame.pack(side=tk.TOP, pady=10, padx=10)

        # URL Input
        tk.Label(main_frame, text="URL (with FUZZ):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.url_entry = tk.Entry(main_frame, width=80)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.url_entry.insert(0, "")

        # OS Type
        tk.Label(main_frame, text="OS Type:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.os_type = tk.StringVar(value="linux")
        os_options = ttk.Combobox(main_frame, textvariable=self.os_type, values=["linux", "windows"], state="readonly", width=27)
        os_options.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Depth
        tk.Label(main_frame, text="Depth:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.depth_spin = tk.Spinbox(main_frame, from_=1, to=10, width=30)
        self.depth_spin.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        self.depth_spin.delete(0, "end")
        self.depth_spin.insert(0, "5")

        # Custom File
        tk.Label(main_frame, text="File:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.file_entry = tk.Entry(main_frame, width=30)
        self.file_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        self.file_entry.insert(0, "/etc/passwd")

        # Filters
        tk.Label(main_frame, text="Status Codes (-fc):").grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.fc_entry = tk.Entry(main_frame, width=30)
        self.fc_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")
        self.fc_entry.insert(0, "200")

        tk.Label(main_frame, text="Size Filter (-fs):").grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.fs_entry = tk.Entry(main_frame, width=30)
        self.fs_entry.grid(row=5, column=1, padx=5, pady=5, sticky="w")
        self.fs_entry.insert(0, "800")

        # Output Area (Extended height)
        self.output_text = scrolledtext.ScrolledText(main_frame, width=80, height=30, wrap=tk.WORD)
        self.output_text.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

        # Configure tag for bold-black text
        bold_font = font.Font(family="Helvetica", size=10, weight="bold")
        self.output_text.tag_configure("bold_black", font=bold_font, foreground="black")

        # Run Button
        self.run_button = tk.Button(main_frame, text="Run", command=self.run_scan)
        self.run_button.grid(row=7, column=0, columnspan=2, pady=5)

        # Quit Button
        self.quit_button = tk.Button(main_frame, text="Quit", command=self.quit)
        self.quit_button.grid(row=8, column=0, columnspan=2, pady=5)

        # Integrate asyncio with Tkinter
        self.root.after(100, self._process_asyncio)

    def _process_asyncio(self):
        self.loop.run_until_complete(self._tick())
        self.root.after(100, self._process_asyncio)

    async def _tick(self):
        await asyncio.sleep(0.01)

    def run_scan(self):
        self.output_text.delete(1.0, tk.END)
        self.hits_found = False  # Reset flag before scan
        url = self.url_entry.get()
        os_type = self.os_type.get()
        depth = int(self.depth_spin.get())
        custom_file = self.file_entry.get()
        fc = self.fc_entry.get().split(',')
        fs = self.fs_entry.get().split(',')

        if 'FUZZ' not in url:
            self.output_text.insert(tk.END, "Error: URL must contain FUZZ parameter\n")
            return
        
        if fs and not all(map(lambda x: re.match(r'[0-9\*\?]+', x), fs)):
            self.output_text.insert(tk.END, "Error: Invalid -fs parameter\n")
            return
        fs = [x.replace("*", "\\d*").replace("?", "\\d?") for x in fs]
        
        if fc and not all(map(lambda x: re.match(r'[0-9\*\?]+', x), fc)):
            self.output_text.insert(tk.END, "Error: Invalid -fc parameter\n")
            return
        fc = [x.replace("*", "\\d*").replace("?", "\\d?") for x in fc]

        asyncio.ensure_future(self._async_scan(url, os_type, depth, custom_file, fc, fs))

    async def _async_scan(self, url, os_type, depth, custom_file, fc, fs):
        inputs = {'url': [url]}
        generator = Generator('http', inputs, depth, os_type, custom_file=custom_file)
        payloads = generator.get_payloads()
        self.output_text.insert(tk.END, f"Generated {len(payloads)} payloads: {payloads}\n")
        
        if yarl.URL(url).scheme in ('http', 'https'):
            engine = HTTPEngine(
                url,
                payloads=payloads,
                callbacks=[self._gui_print_http_result],
                filters=(fc, fs))
            await engine.run()
        
        # Check if no hits were found after scan
        if not self.hits_found:
            self.output_text.insert(tk.END, "No Directory Traversal Vulnerability found in this endpoint\n")

    def _gui_print_http_result(self, result):
        self.hits_found = True  # Mark that a hit was found
        status = result['status']
        size = result['size']
        url = result['url']
        content = result['content']
        
        # Insert status and size normally
        self.output_text.insert(tk.END, f"[200] Size: {size:<6} URL: ")
        
        # Insert URL with bold-black formatting
        start_idx = self.output_text.index(tk.END)
        self.output_text.insert(tk.END, url)
        end_idx = self.output_text.index(tk.END)
        self.output_text.tag_add("bold_black", start_idx, end_idx)
        
        # Insert content and separator
        self.output_text.insert(tk.END, f"\n{content}\n\n")
        self.output_text.see(tk.END)

    def quit(self):
        self.root.quit()

def main():
    root = tk.Tk()
    app = DotDotHuntGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
