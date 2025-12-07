import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import triple_des_backend as tdb
import random

# ---------- helpers ----------
def bits_to_str(bits): return ''.join(str(x) for x in bits)
def bytes_to_bits_readable(b): return ' '.join(format(byte, '08b') for byte in b)
def bits_to_hex(bits): return tdb.bits_to_bytes(bits).hex().upper()
def bytes_to_hex(b): return b.hex().upper()

# ---------- GUI ----------
class TripleDESFixedGUI:
    def __init__(self, root):
        self.root = root
        root.title("Triple DES — Tables & Consolidated Steps")
        # Maximize the window on startup
        root.resizable(True, True) 
        try:
            root.state('zoomed')
        except tk.TclError:
            root.attributes('-fullscreen', False) 

        self.keys = None
        self.mode3 = True
        self.generated_cipher = None
        # Store all three sets of key generation details: {'K1': [...], 'K2': [...], 'K3': [...]}
        self.key_generation_details = None 

        # layout: left (steps), right (tables scrollable), bottom (controls + step output)
        main = ttk.Frame(root)
        main.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Left frame: steps list (static, expandable)
        left = ttk.Frame(main, width=260)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,6))
        
        steps_label = ttk.Label(left, text="Steps / Methods", font=("Segoe UI", 11, "bold"))
        steps_label.pack(anchor=tk.NW, pady=(4,6))

        self.steps = [
            ("Initial Permutation (IP)", "Apply IP to 64-bit block as the first step."),
            ("Key Generation", "PC-1 -> split C,D -> left shifts -> PC-2 => 16 round keys."),
            ("Feistel Round", "Expand R (E), XOR with round key, S-boxes, P permutation, XOR with L."),
            ("16 Rounds", "Repeat the Feistel round 16 times for each DES stage."),
            ("Final Permutation (FP)", "Apply FP after 16 rounds (swap L/R before FP)."),
            ("Triple DES (EDE)", "Encrypt with K1, Decrypt with K2, Encrypt with K3 (or K1 if 2-key)."),
            ("Padding (PKCS#7)", "Pad plaintext to 8-byte multiples before block processing."),
            ("S-Boxes", "Eight S-box lookups reduce 48 bits -> 32 bits per round."),
        ]
        self.step_frames = []
        for title, desc in self.steps:
            hdr = ttk.Frame(left)
            hdr.pack(fill=tk.X, pady=(2,0))
            btn = ttk.Button(hdr, text=title, style="Toolbutton", command=lambda d=desc, f=hdr: self.toggle_detail(hdr, d))
            btn.pack(fill=tk.X, anchor=tk.NW)
            detail = ttk.Label(left, text=desc, wraplength=240, justify=tk.LEFT)
            detail.pack_forget()
            self.step_frames.append((hdr, detail))

        # Right frame: scrollable area with tables
        right_container = ttk.Frame(main)
        right_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        right_label = ttk.Label(right_container, text="DES Tables (8 columns)", font=("Segoe UI", 10, "bold"))
        right_label.pack(anchor=tk.NW)

        # Create a canvas with both vertical and horizontal scrollbars
        canvas_frame = ttk.Frame(right_container)
        canvas_frame.pack(fill=tk.BOTH, expand=True, pady=(4,0))

        self.canvas = tk.Canvas(canvas_frame, highlightthickness=0)
        vscroll = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        hscroll = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL, command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # inner frame that will contain tables
        self.tables_frame = ttk.Frame(self.canvas)
        self.canvas_window = self.canvas.create_window((0,0), window=self.tables_frame, anchor='nw')

        # populate tables
        self._populate_tables_initial()

        # configure scrolling region
        self.tables_frame.update_idletasks()
        self.canvas.config(scrollregion=self.canvas.bbox("all"))

        # bind mousewheel to scroll vertically
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Bottom frame: controls and steps output
        bottom = ttk.Frame(root)
        bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=6, pady=6)

        # Controls: plaintext input, mode, generate keys, encrypt, decrypt
        ctrl = ttk.Frame(bottom)
        ctrl.pack(fill=tk.X, pady=(0,6))

        ttk.Label(ctrl, text="Plaintext (UTF-8):").grid(row=0, column=0, sticky=tk.W)
        self.entry_plain = ttk.Entry(ctrl, width=60)
        self.entry_plain.grid(row=0, column=1, columnspan=3, padx=6, sticky=tk.W)

        ttk.Label(ctrl, text="Mode:").grid(row=1, column=0, sticky=tk.W, pady=(6,0))
        self.mode_var = tk.StringVar(value='3')
        ttk.Radiobutton(ctrl, text="2-key", variable=self.mode_var, value='2').grid(row=1, column=1, sticky=tk.W, pady=(6,0))
        ttk.Radiobutton(ctrl, text="3-key", variable=self.mode_var, value='3').grid(row=1, column=2, sticky=tk.W, pady=(6,0))

        self.btn_gen = ttk.Button(ctrl, text="Generate Random Keys", command=self.generate_random_keys)
        self.btn_gen.grid(row=0, column=4, padx=6)
        self.btn_encrypt = ttk.Button(ctrl, text="Encrypt & Show Steps", command=self.run_encrypt)
        self.btn_encrypt.grid(row=0, column=5, padx=6)
        
        # NEW BUTTON: Calls a selector function
        self.btn_key_steps = ttk.Button(ctrl, text="Show Key Generation Steps (K1/K2/K3)", command=self.open_key_details_selector)
        self.btn_key_steps.grid(row=1, column=3, padx=6, pady=(6,0)) 
        
        self.btn_decrypt = ttk.Button(ctrl, text="Decrypt (generated keys)", command=self.run_decrypt_dialog)
        self.btn_decrypt.grid(row=1, column=5, padx=6, pady=(6,0))
        self.btn_save = ttk.Button(ctrl, text="Save Steps Output", command=self.save_output)
        self.btn_save.grid(row=1, column=4, padx=6, pady=(6,0))

        # Keys display small line
        self.keys_display = ttk.Label(bottom, text="No keys generated yet")
        self.keys_display.pack(anchor=tk.W)

        # Steps output area (scrolled text)
        steps_out_frame = ttk.LabelFrame(root, text="Step-by-step Output (detailed per-block / per-round)")
        steps_out_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=6, pady=(0,6))
        # Note: wrap=tk.NONE ensures horizontal scrolling for long binary strings
        self.txt_steps = scrolledtext.ScrolledText(steps_out_frame, height=12, wrap=tk.NONE) 
        self.txt_steps.pack(fill=tk.BOTH, expand=True)

    # ---------- toggle detail for a step ----------
    def toggle_detail(self, header_frame, description):
        for hdr, det in self.step_frames:
            if hdr is header_frame:
                if det.winfo_ismapped():
                    det.pack_forget()
                else:
                    det.pack(anchor=tk.W, pady=(0,6))
                break

    # ---------- populate tables (8 columns) ----------
    def _populate_tables_initial(self):
        tf = self.tables_frame
        for widget in tf.winfo_children():
            widget.destroy()

        padx = 6
        pady = 6

        def grid_table(title, data_list):
            tlabel = ttk.Label(tf, text=title, font=("Segoe UI", 9, "bold"))
            tlabel.pack(anchor=tk.W, pady=(pady//2, 2), padx=4)

            gridf = ttk.Frame(tf)
            gridf.pack(anchor=tk.W, padx=4)

            data = [str(x) for x in data_list]
            cols = 8
            rows = (len(data) + cols - 1) // cols
            idx = 0
            for r in range(rows):
                for c in range(cols):
                    if idx < len(data):
                        lbl = ttk.Label(gridf, text=data[idx], borderwidth=1, relief="ridge", anchor=tk.CENTER, width=9)
                        lbl.grid(row=r, column=c, padx=1, pady=1)
                    else:
                        lbl = ttk.Label(gridf, text="", borderwidth=0, relief="flat", width=9)
                        lbl.grid(row=r, column=c, padx=1, pady=1)
                    idx += 1

        # IP, FP, E, P, PC1, PC2, SHIFTS
        grid_table("IP (Initial Permutation)", tdb.IP)
        grid_table("FP (Final Permutation)", tdb.FP)
        grid_table("E (Expansion)", tdb.E)
        grid_table("P (Permutation after S-box)", tdb.P)
        grid_table("PC-1 (Key initial permute)", tdb.PC1)
        grid_table("PC-2 (Key compression)", tdb.PC2)
        grid_table("SHIFTS (Left shifts each round)", tdb.SHIFTS)

        # SBOX: keep matrix style
        sbox_label = ttk.Label(tf, text="S-Boxes (SBOX[0]..SBOX[7])", font=("Segoe UI", 9, "bold"))
        sbox_label.pack(anchor=tk.W, pady=(8,2), padx=4)

        for i, s in enumerate(tdb.SBOX):
            sframe = ttk.Frame(tf)
            sframe.pack(anchor=tk.W, padx=4, pady=(2,4))
            title = ttk.Label(sframe, text=f"SBOX[{i}]", font=("Segoe UI", 9, "underline"))
            title.pack(anchor=tk.W)
            for row in s:
                rowstr = '  '.join(f"{v:2d}" for v in row)
                rlbl = ttk.Label(sframe, text=rowstr, justify=tk.LEFT, font=("Courier", 9))
                rlbl.pack(anchor=tk.W)
        
    # ---------- mouse wheel scroll ----------
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(-1 * int(event.delta / 120), "units")

    # ---------- generate random keys ----------
    def generate_random_keys(self):
        mode3 = (self.mode_var.get() == '3')
        k1 = bytes(random.getrandbits(8) for _ in range(8))
        k2 = bytes(random.getrandbits(8) for _ in range(8))
        k3 = bytes(random.getrandbits(8) for _ in range(8))
        
        self.keys = (k1, k2, k3)
        self.mode3 = mode3
        self.key_generation_details = None # Reset details
        self.update_keys_display()

    def update_keys_display(self):
        if self.keys:
            k1,k2,k3 = self.keys
            s = f"K1={k1.hex().upper()}  K2={k2.hex().upper()}"
            if self.mode3:
                s += f"  K3={k3.hex().upper()}"
            else:
                s += f"  K3=(same as K1 in 2-key mode)"
        else:
            s = "No keys generated yet"
        self.keys_display.config(text=s)
    
    # NEW METHOD: Selector for Key Details
    def open_key_details_selector(self):
        if not self.key_generation_details:
            messagebox.showwarning("No Details", "Please run 'Encrypt & Show Steps' first to generate and store key details.")
            return

        # Simple dialog to choose K1, K2, or K3
        key_to_show = simpledialog.askstring("Select Key", "Enter the key number to view steps (1, 2, or 3):", initialvalue="1")
        
        if key_to_show is None:
            return
        
        key_name = f"K{key_to_show}"
        
        if key_name not in self.key_generation_details:
            if key_to_show in ['1', '2', '3']:
                 messagebox.showerror("Error", f"Key {key_to_show} details not available. Run encryption in 3-key mode or check key details generation.")
            else:
                 messagebox.showerror("Error", "Invalid selection. Please enter 1, 2, or 3.")
            return

        self.show_key_details(key_name)

    # UPDATED METHOD: Show Key Generation Details (now accepts key_name)
    def show_key_details(self, key_name):
        key_details = self.key_generation_details[key_name]
        
        # Toplevel window for dedicated detail display
        details_window = tk.Toplevel(self.root)
        details_window.title(f"{key_name} Round Key Generation Details")
        details_window.geometry("850x600")

        # ScrolledText area
        text_area = scrolledtext.ScrolledText(details_window, wrap=tk.NONE, width=100, height=35, font=("Courier", 10))
        text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Get the original key used for this stage
        original_key = self.keys[int(key_name[1]) - 1]
        
        text_area.insert(tk.END, f"--- {key_name} ROUND KEY GENERATION PROCESS ---\n", 'header')
        text_area.insert(tk.END, f"Input Key {key_name} (Hex): {bytes_to_hex(original_key)}\n\n", 'key_input')

        for detail in key_details:
            step = detail['step']
            info = detail['info']
            output = detail['output']
            
            tag = 'default'
            if 'PC-1' in step: tag = 'pc1'
            elif 'Split' in step: tag = 'split'
            elif 'Shift' in step: tag = 'shift'
            elif 'Round Key K' in step: tag = 'key_output'

            text_area.insert(tk.END, f"--- {step} ---\n", tag)
            text_area.insert(tk.END, f"INFO: {info}\n", 'info')
            text_area.insert(tk.END, f"OUTPUT:\n{output}\n\n", 'output')

        # Configure tags
        text_area.tag_configure('header', font=('Courier', 12, 'bold'), foreground='blue')
        text_area.tag_configure('key_input', font=('Courier', 10, 'bold'), foreground='darkgreen')
        text_area.tag_configure('pc1', foreground='purple')
        text_area.tag_configure('split', foreground='brown')
        text_area.tag_configure('shift', foreground='darkorange')
        text_area.tag_configure('key_output', font=('Courier', 10, 'bold'), foreground='red')
        text_area.tag_configure('info', font=('Courier', 9, 'italic'), foreground='gray50')

        text_area.config(state=tk.DISABLED) # Make it read-only
    # --------------------------------------------------------------------


    # ---------- encryption with detailed steps (now includes all round flow) ----------
    def run_encrypt(self):
        self.txt_steps.configure(state='normal')
        self.txt_steps.delete('1.0', tk.END)

        plaintext = self.entry_plain.get().encode('utf-8')
        mode3 = (self.mode_var.get() == '3')
        self.mode3 = mode3

        if not self.keys:
            self.generate_random_keys()
        
        k1, k2, k3_original = self.keys
        
        try:
            # CAPTURE key_details from the backend
            cipher_bytes, self.keys, self.key_generation_details = tdb.triple_des_encrypt(
                plaintext, k1, k2, k3_original, mode3
            )
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to run encryption: {e}")
            return

        self.generated_cipher = cipher_bytes
        
        # Determine the key actually used for K3 (K1 or K3_original)
        k3_used = self.keys[2] 
        
        # Generate round keys manually for display of per-round steps (using the details function to match backend)
        rk1, _ = tdb.generate_round_keys_with_details(k1)
        rk2, _ = tdb.generate_round_keys_with_details(k2)
        rk3, _ = tdb.generate_round_keys_with_details(k3_used)

        # show keys & round keys (as you had it)
        self.txt_steps.insert(tk.END, "=== Keys ===\n")
        self.txt_steps.insert(tk.END, f"K1: {k1.hex().upper()}\nK2: {k2.hex().upper()}\n")
        if mode3:
            self.txt_steps.insert(tk.END, f"K3: {k3_used.hex().upper()}\n")
        else:
            self.txt_steps.insert(tk.END, f"(2-key mode: K3 = {k1.hex().upper()})\n")
            
        self.txt_steps.insert(tk.END, "\n=== Round Keys (hex) ===\n")
        for i, rk in enumerate(rk1, 1):
            self.txt_steps.insert(tk.END, f"K1 R{i}: {bits_to_hex(rk)}\n")
        for i, rk in enumerate(rk2, 1):
            self.txt_steps.insert(tk.END, f"K2 R{i}: {bits_to_hex(rk)}\n")
        for i, rk in enumerate(rk3, 1):
            self.txt_steps.insert(tk.END, f"K3 R{i}: {bits_to_hex(rk)}\n")
        self.txt_steps.insert(tk.END, "\n")

        data_p = tdb.pkcs7_pad(plaintext, 8)
        self.txt_steps.insert(tk.END, f"Plaintext hex: {plaintext.hex().upper()}\nPadded hex: {data_p.hex().upper()}\n\n")

        out_all = bytearray()
        
        # The subsequent per-block/per-round display logic (Stage 1, 2, 3) 

        for bi in range(0, len(data_p), 8):
            block = data_p[bi:bi+8]
            block_num = bi//8
            self.txt_steps.insert(tk.END, f"==================== BLOCK {block_num} ====================\n")
            self.txt_steps.insert(tk.END, f"Block hex: {block.hex().upper()}\nBlock bits: {bytes_to_bits_readable(block)}\n\n")

            # --- STAGE 1: ENCRYPT with K1 ---
            self.txt_steps.insert(tk.END, "--- Stage 1: Encrypt with K1 ---\n")
            bits = tdb.bytes_to_bits(block)
            ip = tdb.permute(bits, tdb.IP)
            L, R = ip[:32], ip[32:]
            Lcur, Rcur = L[:], R[:]
            
            for rnum, rk in enumerate(rk1, 1):
                expanded = tdb.permute(Rcur, tdb.E)
                xored = tdb.xor(expanded, rk)
                s_out = tdb.sbox_sub(xored)
                p_out = tdb.permute(s_out, tdb.P)
                newL = Rcur
                newR = tdb.xor(Lcur, p_out)
                
                # CONSOLIDATED ROUND FLOW DETAILS
                self.txt_steps.insert(tk.END, f"\n- Round {rnum} -\n")
                self.txt_steps.insert(tk.END, f"L (before): {bits_to_str(Lcur)}\n")
                self.txt_steps.insert(tk.END, f"R (before): {bits_to_str(Rcur)}\n")
                self.txt_steps.insert(tk.END, f"Expanded R: {bits_to_str(expanded)}\n")
                self.txt_steps.insert(tk.END, f"XOR with key: {bits_to_str(xored)}\n")
                self.txt_steps.insert(tk.END, f"S-box output: {bits_to_str(s_out)}\n")
                self.txt_steps.insert(tk.END, f"P permutation: {bits_to_str(p_out)}\n")
                self.txt_steps.insert(tk.END, f"L (after):  {bits_to_str(newL)}\n")
                self.txt_steps.insert(tk.END, f"R (after):  {bits_to_str(newR)}\n")
                
                Lcur, Rcur = newL, newR

            preout = Rcur + Lcur
            out1 = tdb.bits_to_bytes(tdb.permute(preout, tdb.FP))
            self.txt_steps.insert(tk.END, f"\n--- Stage 1 Complete ---\nOutput hex: {out1.hex().upper()}\n\n")


            # --- STAGE 2: DECRYPT with K2 (reverse key order) ---
            self.txt_steps.insert(tk.END, "--- Stage 2: Decrypt with K2 (Keys reversed) ---\n")
            bits2 = tdb.bytes_to_bits(out1)
            ip2 = tdb.permute(bits2, tdb.IP)
            L2, R2 = ip2[:32], ip2[32:]
            Lcur, Rcur = L2[:], R2[:]

            for rnum, rk in enumerate(rk2[::-1], 1): # rk2[::-1] gives K2 keys in reverse for decryption
                expanded = tdb.permute(Rcur, tdb.E)
                xored = tdb.xor(expanded, rk)
                s_out = tdb.sbox_sub(xored)
                p_out = tdb.permute(s_out, tdb.P)
                newL = Rcur
                newR = tdb.xor(Lcur, p_out)

                # CONSOLIDATED ROUND FLOW DETAILS
                self.txt_steps.insert(tk.END, f"\n- Round {rnum} -\n")
                self.txt_steps.insert(tk.END, f"L (before): {bits_to_str(Lcur)}\n")
                self.txt_steps.insert(tk.END, f"R (before): {bits_to_str(Rcur)}\n")
                self.txt_steps.insert(tk.END, f"Expanded R: {bits_to_str(expanded)}\n")
                self.txt_steps.insert(tk.END, f"XOR with key: {bits_to_str(xored)}\n")
                self.txt_steps.insert(tk.END, f"S-box output: {bits_to_str(s_out)}\n")
                self.txt_steps.insert(tk.END, f"P permutation: {bits_to_str(p_out)}\n")
                self.txt_steps.insert(tk.END, f"L (after):  {bits_to_str(newL)}\n")
                self.txt_steps.insert(tk.END, f"R (after):  {bits_to_str(newR)}\n")

                Lcur, Rcur = newL, newR
            
            preout2 = Rcur + Lcur
            out2 = tdb.bits_to_bytes(tdb.permute(preout2, tdb.FP))
            self.txt_steps.insert(tk.END, f"\n--- Stage 2 Complete ---\nOutput hex: {out2.hex().upper()}\n\n")

            # --- STAGE 3: ENCRYPT with K3 ---
            self.txt_steps.insert(tk.END, "--- Stage 3: Encrypt with K3 ---\n")
            bits3 = tdb.bytes_to_bits(out2)
            ip3 = tdb.permute(bits3, tdb.IP)
            L3, R3 = ip3[:32], ip3[32:]
            Lcur, Rcur = L3[:], R3[:]

            for rnum, rk in enumerate(rk3, 1):
                expanded = tdb.permute(Rcur, tdb.E)
                xored = tdb.xor(expanded, rk)
                s_out = tdb.sbox_sub(xored)
                p_out = tdb.permute(s_out, tdb.P)
                newL = Rcur
                newR = tdb.xor(Lcur, p_out)
                
                # CONSOLIDATED ROUND FLOW DETAILS
                self.txt_steps.insert(tk.END, f"\n- Round {rnum} -\n")
                self.txt_steps.insert(tk.END, f"L (before): {bits_to_str(Lcur)}\n")
                self.txt_steps.insert(tk.END, f"R (before): {bits_to_str(Rcur)}\n")
                self.txt_steps.insert(tk.END, f"Expanded R: {bits_to_str(expanded)}\n")
                self.txt_steps.insert(tk.END, f"XOR with key: {bits_to_str(xored)}\n")
                self.txt_steps.insert(tk.END, f"S-box output: {bits_to_str(s_out)}\n")
                self.txt_steps.insert(tk.END, f"P permutation: {bits_to_str(p_out)}\n")
                self.txt_steps.insert(tk.END, f"L (after):  {bits_to_str(newL)}\n")
                self.txt_steps.insert(tk.END, f"R (after):  {bits_to_str(newR)}\n")
                
                Lcur, Rcur = newL, newR
            
            preout3 = Rcur + Lcur
            out3 = tdb.bits_to_bytes(tdb.permute(preout3, tdb.FP))
            self.txt_steps.insert(tk.END, f"\n--- Stage 3 Complete ---\nOutput hex: {out3.hex().upper()}\n")
            self.txt_steps.insert(tk.END, f"Ciphertext for Block {block_num}: {out3.hex().upper()}\n")
            self.txt_steps.insert(tk.END, "\n")

            out_all.extend(out3)

        self.generated_cipher = bytes(out_all)
        self.txt_steps.insert(tk.END, "=== Final Ciphertext (hex) ===\n")
        self.txt_steps.insert(tk.END, out_all.hex().upper() + "\n")
        self.txt_steps.configure(state='disabled')

        # update keys display
        self.update_keys_display()
        messagebox.showinfo("Done", "Encryption completed. Detailed per-round flow is now available in the 'Step-by-step Output' area. Key Generation steps are available via the new button.")

    # ---------- Decrypt with generated keys ----------
    def run_decrypt_dialog(self):
        if not self.keys:
            messagebox.showerror("No keys", "Generate keys first.")
            return
        
        k1, k2, k3_original = self.keys

        default = getattr(self, 'generated_cipher', b'').hex().upper()
        s = simpledialog.askstring("Decrypt", "Enter ciphertext hex (leave blank to use last generated):", initialvalue=default)
        if s is None:
            return
        if not s:
            if not default:
                messagebox.showerror("No ciphertext", "No ciphertext available.")
                return
            s = default
            
        try:
            cbytes = bytes.fromhex(s)
        except Exception as e:
            messagebox.showerror("Invalid hex", str(e))
            return
            
        try:
            plain = tdb.triple_des_decrypt(cbytes, k1, k2, k3_original, self.mode3)
        except Exception as e:
            messagebox.showerror("Decryption failed", str(e))
            return
            
        try:
            text = plain.decode('utf-8')
            messagebox.showinfo("Decrypted (utf-8)", text)
        except Exception:
            messagebox.showinfo("Decrypted (hex)", plain.hex().upper())

    # ---------- save step output ----------
    def save_output(self):
        content = self.txt_steps.get('1.0', tk.END).strip()
        if not content:
            messagebox.showwarning("No content", "No step output to save. Run encryption first.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files",".txt"),("All files",".*")])
        if not f:
            return
        with open(f, 'w', encoding='utf-8') as fh:
            fh.write(content)
        messagebox.showinfo("Saved", f"Saved to {f}")

# ---------- main ----------
def main():
    root = tk.Tk()
    app = TripleDESFixedGUI(root)
    root.mainloop()

if __name__ == "__main__":

    main()


