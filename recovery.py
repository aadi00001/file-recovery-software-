import os
import zipfile

def is_valid_docx(file_path):
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            required_files = ['word/document.xml', '[Content_Types].xml']
            return all(f in z.namelist() for f in required_files)
    except zipfile.BadZipFile:
        return False

def recover_raw_files(comm, drive_letter, output_dir):
    drive = f"\\\\.\\{drive_letter.upper()}:"       #tells in ehich drive we are recovering.
    block_size = 4096  # or 8192 or even 65536
    offset = 0
    rcvd = 0

    signatures = [
        {"ext": "jpg", "header": b'\xff\xd8\xff\xe0\x00\x10\x4a\x46', "footer": b'\xff\xd9'},
        {"ext": "png", "header": b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', "footer": b'\x49\x45\x4e\x44\xae\x42\x60\x82'},
        {"ext": "pdf", "header": b'%PDF', "footer": b'%%EOF'},
        {"ext": "docx", "header": b'\x50\x4B\x03\x04', "footer": b'\x50\x4B\x05\x06'},
        {"ext": "zip", "header": b'\x50\x4B\x03\x04', "footer": b'\x50\x4B\x05\x06'}
    ]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        with open(drive, "rb") as fileD:#rd: raw bytes form mai khola aur read karo
            comm.log_signal.emit(f"[RAW] Scanning raw bytes from: {drive}")
            data = fileD.read(block_size)
            while data:
                for sig in signatures:
                    start = data.find(sig["header"])
                    start = data.find(sig["header"])
                    if start >= 0:
                        temp_path = os.path.join(output_dir, f"recovered_{rcvd}.{sig['ext']}")
                        comm.log_signal.emit(f"[FOUND] {sig['ext'].upper()} at offset {hex(offset * block_size + start)} → {temp_path}")
                        
                        with open(temp_path, "wb") as out:
                            out.write(data[start:])
                            while True:
                                chunk = fileD.read(block_size)
                                if not chunk:
                                    break
                                end = chunk.find(sig["footer"])
                                if end >= 0:
                                    out.write(chunk[:end + len(sig["footer"])])
                                    break
                                else:
                                    out.write(chunk)

                        # File is now fully written and closed
                        if sig["ext"] == "docx":
                            if not is_valid_docx(temp_path):
                                os.remove(temp_path)
                                comm.log_signal.emit(f"[SKIPPED] Corrupted DOCX discarded: {temp_path}")
                                break  # Move to next block
                        comm.log_signal.emit(f"[RECOVERED] {temp_path}")
                        rcvd += 1
                        break  # Move to next block

                offset += 1
                progress = min(int((offset * block_size) / (128 * 1024 * 1024) * 100), 100)  # Simulate up to 128MB
                comm.progress_signal.emit(progress)
                data = fileD.read(block_size)
    except Exception as e:
        comm.log_signal.emit(f"[ERROR] Recovery failed: {e}")
        return

    comm.log_signal.emit(f"[DONE] {rcvd} file(s) recovered.")
    comm.recovery_status_signal.emit(f"Raw recovery complete: {rcvd} file(s)")
    comm.progress_signal.emit(100)
