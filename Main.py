import customtkinter as ctk
from tkinter import filedialog, messagebox
import socket
import ssl
import threading
import hashlib
import datetime
import re
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

# --- Configuración Visual Base (Estética LangeApps / Cyber) ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG_MAIN = "#07090b"        # Fondo principal (casi negro)
BG_FRAME = "#0e1318"       # Fondo de los paneles
ACCENT = "#11a87e"         # Verde mate (LangeApps)
BORDER_DARK = "#1a2b35"    # Bordes sutiles
TEXT_MAIN = "#d4d4d4"      # Texto claro normal

# --- Diccionario de Traducciones ---
LANG = {
    'es': {
        'title': "CERTANALYZER v1.6.1 - TOOLKIT PKI AVANZADO",
        'lbl_ip': "IP / HOST:",
        'lbl_port': "PUERTO:",
        'lbl_sni': "SNI (FQDN):",
        'btn_analyze': "ANALIZAR RED",
        'btn_export': "EXPORTAR LOG (TXT)",
        'btn_export_certs': "DESCARGAR CERTS (.PEM)",
        'btn_lang': "EN",
        'conn_start': "[*] Iniciando conexión a {ip}:{port} con SNI '{sni}'...",
        'conn_ok': "[+] Conexión exitosa: {tls} (Cifrado: {cipher})\n",
        'err_py_ver': "[-] ERROR: Tu versión de Python no soporta get_unverified_chain(). Requiere Python 3.10+.",
        'err_no_cert': "[-] El servidor no presentó ningún certificado.",
        'chain_hdr': "\n>>> CADENA DE CERTIFICADOS PRESENTADA ({count} certificados) <<<\n",
        'issuer': "Emisor (CA)",
        'subject': "Sujeto",
        'valid_from': "Válido desde",
        'valid_to': "Válido hasta",
        'fingerprint': "Huella SHA-256",
        'cert_type': "Tipo de Certificado",
        'type_ov': "Organization Validation (OV) - Org: {org} ({country})",
        'type_dv': "Domain Validation (DV)",
        'sans': "SANs (Nombres alternativos)",
        'ocsp': "URL de OCSP",
        'ocsp_none': "No declarada",
        'diag_hdr': "\n>>> DIAGNÓSTICO DE LA CADENA & INGENIERÍA PKI <<<\n",
        'err_expired': "[!] ALERTA CRÍTICA: El certificado [{i}] ('{cn}') está VENCIDO (Expiró el {date}).",
        'warn_expiring': "[!] ADVERTENCIA: El certificado [{i}] ('{cn}') está próximo a vencer (Expira en {days} días).",
        'err_break': "[!] RUPTURA DE CADENA detectada entre el certificado [{i}] y el [{next_i}].",
        'err_break_iss': "    El cert [{i}] dice ser emitido por: {issuer}",
        'err_break_sub': "    Pero el cert [{next_i}] entregado es: {subject}",
        'err_crypto': "    [X] Fallo de firma criptográfica: {e}",
        'ok_chain_link': "[✓] Criptográficamente validado: La firma del cert [{i}] verificada con la clave pública de [{next_i}].",
        'ok_chain': "[✓] Orden de cadena correcto. Todos los certificados pasaron la prueba de firma matemática.",
        'warn_missing': "[-] El servidor solo entregó el certificado final. Faltan certificados intermedios (CA).",
        'warn_root': "[i] INFO: El último certificado es un Root CA (Auto-firmado).",
        'root_trusted': "[✓] VALIDADO: La CA Root presentada existe en el almacén de confianza de este sistema.",
        'root_untrusted': "[!] ALERTA CRÍTICA: CA Root auto-firmada NO EXISTE en el almacén local. Posible MITM.",
        'ok_root': "[i] INFO: El servidor omite la CA Root.",
        'compat_r46': "[i] LEGACY: La cadena incluye 'Sectigo R46'.",
        'compat_usertrust': "[i] LEGACY: La cadena encadena hacia 'USERTrust RSA'.",
        'hsts_hdr': "\n>>> VALIDACIÓN HTTP (HSTS) <<<\n",
        'hsts_ok': "[✓] HSTS Habilitado: {val}",
        'hsts_missing': "[!] HSTS Ausente: El servidor no envía la cabecera Strict-Transport-Security.",
        'hsts_not_http': "[-] No se pudo validar HSTS (La respuesta no parece ser HTTP).",
        'hsts_timeout': "[-] Tiempo de espera agotado al intentar leer cabeceras HTTP.",
        'hsts_err': "[-] Error al verificar HSTS: {e}",
        'err_fatal': "\n[ERROR] Ocurrió un fallo durante el análisis: {e}",
        'exp_title': "Guardar Reporte",
        'exp_success': "Operación exitosa.",
        'exp_err': "Error: {e}",
        'lbl_local_mode': "ANÁLISIS DE ARCHIVOS LOCALES",
        'btn_load_cer': "CARGAR .CER/.PEM/.P12",
        'btn_load_key': "CARGAR .KEY",
        'btn_verify_local': "ANALIZAR / VERIFICAR",
        'btn_clear': "LIMPIAR",
        'btn_concat': "CONCATENAR",
        'btn_split': "DIVIDIR (SPLIT)",
        'btn_convert': "CONVERTIR (PEM/DER)",
        'btn_export_p12': "CREAR P12",
        'no_file': "Ninguno seleccionado",
        'local_hdr': ">>> ANÁLISIS DE ARCHIVOS LOCALES <<<\n",
        'ask_pwd_title': "Llave / Almacén Encriptado",
        'ask_pwd_msg': "El archivo está encriptado.\nIngrese la contraseña:",
        'ask_pwd_msg_p12': "Ingrese la contraseña del archivo P12/PFX\n(Déjelo en blanco si no tiene):",
        'ask_pwd_new_p12': "Ingrese la contraseña para el nuevo archivo P12\n(Déjelo en blanco para no usar contraseña):",
        'err_pwd': "[-] Contraseña incorrecta o formato no soportado.",
        'err_read_cert': "[-] Error procesando certificado: {e}",
        'err_read_key': "[-] Error procesando llave: {e}",
        'match_ok': "\n[✓] MATCH EXITOSO: El certificado [{idx}] CORRESPONDE matemáticamente a la llave privada.",
        'match_fail': "\n[X] NO MATCH: Ningún certificado seleccionado pertenece a la llave privada.",
        'warn_no_cert_sel': "Debes seleccionar al menos un archivo de certificado.",
        'warn_no_cert_data': "No hay certificados asociados a esta pestaña para exportar.",
        'warn_p12_needs_key': "Para crear un P12 necesitas cargar una Llave Privada y al menos un Certificado.",
        'msg_split_ok': "Se separaron {n} bloque(s) en la carpeta elegida.",
        'msg_conv_pem': "Convertido a formato de texto PEM exitosamente.",
        'msg_conv_der': "Convertido a formato binario DER exitosamente."
    },
    'en': {
        'title': "CERTANALYZER v1.6.1 - ADVANCED PKI TOOLKIT",
        'lbl_ip': "IP / HOST:",
        'lbl_port': "PORT:",
        'lbl_sni': "SNI (FQDN):",
        'btn_analyze': "ANALYZE NET",
        'btn_export': "EXPORT LOG (TXT)",
        'btn_export_certs': "DOWNLOAD CERTS (.PEM)",
        'btn_lang': "ES",
        'conn_start': "[*] Initiating connection to {ip}:{port} with SNI '{sni}'...",
        'conn_ok': "[+] Connection successful: {tls} (Cipher: {cipher})\n",
        'err_py_ver': "[-] ERROR: Your Python version doesn't support get_unverified_chain(). Requires Python 3.10+.",
        'err_no_cert': "[-] The server did not present any certificates.",
        'chain_hdr': "\n>>> CERTIFICATE CHAIN PRESENTED ({count} certificates) <<<\n",
        'issuer': "Issuer (CA)",
        'subject': "Subject",
        'valid_from': "Valid from",
        'valid_to': "Valid until",
        'fingerprint': "SHA-256 Fingerprint",
        'cert_type': "Certificate Type",
        'type_ov': "Organization Validation (OV) - Org: {org} ({country})",
        'type_dv': "Domain Validation (DV)",
        'sans': "SANs (Alternative Names)",
        'ocsp': "OCSP URL",
        'ocsp_none': "Not declared",
        'diag_hdr': "\n>>> CHAIN DIAGNOSTICS & PKI ENGINEERING <<<\n",
        'err_expired': "[!] CRITICAL ALERT: Certificate [{i}] ('{cn}') is EXPIRED (Expired on {date}).",
        'warn_expiring': "[!] WARNING: Certificate [{i}] ('{cn}') is expiring soon (Expires in {days} days).",
        'err_break': "[!] CHAIN BREAK detected between certificate [{i}] and [{next_i}].",
        'err_break_iss': "    Cert [{i}] claims to be issued by: {issuer}",
        'err_break_sub': "    But cert [{next_i}] delivered is: {subject}",
        'err_crypto': "    [X] Cryptographic signature failure: {e}",
        'ok_chain_link': "[✓] Cryptographically validated: Cert [{i}]'s signature was successfully verified.",
        'ok_chain': "[✓] The chain order is correct. All intermediate certificates passed the signature test.",
        'warn_missing': "[-] The server only delivered the leaf certificate. Intermediate (CA) certificates are likely MISSING.",
        'warn_root': "[i] INFO: The last certificate is a Root CA (Self-signed).",
        'root_trusted': "[✓] VALIDATED: The presented Root CA exists in this OS's trust store.",
        'root_untrusted': "[!] CRITICAL ALERT: The presented Root CA is self-signed but DOES NOT EXIST in the local trust store.",
        'ok_root': "[i] INFO: The server omits the Root CA.",
        'compat_r46': "[i] LEGACY: The chain includes 'Sectigo R46'.",
        'compat_usertrust': "[i] LEGACY: The chain chains up to 'USERTrust RSA'.",
        'hsts_hdr': "\n>>> HTTP VALIDATION (HSTS) <<<\n",
        'hsts_ok': "[✓] HSTS Enabled: {val}",
        'hsts_missing': "[!] HSTS Missing: The server does not send the Strict-Transport-Security header.",
        'hsts_not_http': "[-] Could not validate HSTS (The response does not appear to be HTTP).",
        'hsts_timeout': "[-] Timeout while attempting to read HTTP headers.",
        'hsts_err': "[-] Error verifying HSTS: {e}",
        'err_fatal': "\n[ERROR] A failure occurred during analysis: {e}",
        'exp_title': "Save Report",
        'exp_success': "Operation successful.",
        'exp_err': "Error: {e}",
        'lbl_local_mode': "LOCAL FILE ANALYSIS & TOOLS",
        'btn_load_cer': "LOAD .CER/.PEM/.P12",
        'btn_load_key': "LOAD .KEY",
        'btn_verify_local': "ANALYZE / VERIFY",
        'btn_clear': "CLEAR",
        'btn_concat': "CONCATENATE",
        'btn_split': "SPLIT BLOCKS",
        'btn_convert': "CONVERT (PEM/DER)",
        'btn_export_p12': "CREATE P12",
        'no_file': "None selected",
        'local_hdr': ">>> LOCAL FILE ANALYSIS <<<\n",
        'ask_pwd_title': "Encrypted Key / Keystore",
        'ask_pwd_msg': "The file is encrypted.\nEnter password:",
        'ask_pwd_msg_p12': "Enter P12/PFX password\n(Leave blank if none):",
        'ask_pwd_new_p12': "Enter password for the new P12 file\n(Leave blank for no password):",
        'err_pwd': "[-] Incorrect password or unsupported format.",
        'err_read_cert': "[-] Error processing certificate: {e}",
        'err_read_key': "[-] Error processing key: {e}",
        'match_ok': "\n[✓] SUCCESSFUL MATCH: Certificate [{idx}] mathematically CORRESPONDS to the provided private key.",
        'match_fail': "\n[X] NO MATCH: No selected certificate belongs to this key.",
        'warn_no_cert_sel': "You must select at least a certificate file.",
        'warn_no_cert_data': "No certificates associated with this tab to export.",
        'warn_p12_needs_key': "To create a P12 you need to load a Private Key and at least one Certificate.",
        'msg_split_ok': "Successfully separated {n} block(s) into the chosen folder.",
        'msg_conv_pem': "Successfully converted to PEM text format.",
        'msg_conv_der': "Successfully converted to DER binary format."
    }
}

class SSLInspectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.current_lang = 'es'
        
        self.local_cert_paths = [] 
        self.local_key_path = None
        
        self.tab_count = 0
        self.tabs_textboxes = {}
        
        # Diccionario universal para guardar data de la pestaña actual (sea Red o Local)
        # Formato: {"certs": [x509_obj, ...], "key": private_key_obj_o_None}
        self.tabs_cert_data = {} 
        
        self.title(LANG[self.current_lang]['title'])
        self.geometry("1150x880")
        self.configure(fg_color=BG_MAIN)
        
        self.font_title = ctk.CTkFont(family="Segoe UI", size=24, weight="bold")
        self.font_label = ctk.CTkFont(family="Consolas", size=13, weight="bold")
        self.font_entry = ctk.CTkFont(family="Consolas", size=14)
        self.font_terminal = ctk.CTkFont(family="Consolas", size=13)

        self._build_ui()

    def _build_ui(self):
        # --- Top Bar ---
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        self.lbl_title = ctk.CTkLabel(top_frame, text="CERTANALYZER / TOOLKIT", font=self.font_title, text_color=ACCENT)
        self.lbl_title.pack(side="left")
        
        self.btn_lang = ctk.CTkButton(top_frame, text=LANG[self.current_lang]['btn_lang'], width=40,
                                      fg_color="transparent", border_width=1, border_color=ACCENT, text_color=ACCENT,
                                      hover_color="#003322", corner_radius=0, font=self.font_label,
                                      command=self.toggle_language)
        self.btn_lang.pack(side="right")

        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # --- Frame Entradas RED ---
        net_frame = ctk.CTkFrame(main_container, fg_color=BG_FRAME, border_width=1, border_color=BORDER_DARK, corner_radius=0)
        net_frame.pack(fill="x", pady=(0, 15))
        
        net_frame.grid_columnconfigure(0, weight=4) 
        net_frame.grid_columnconfigure(1, weight=1) 
        net_frame.grid_columnconfigure(2, weight=2) 
        net_frame.grid_columnconfigure(3, weight=0) 
        
        lbl_ip = ctk.CTkLabel(net_frame, text=LANG[self.current_lang]['lbl_ip'], font=self.font_label, text_color=TEXT_MAIN)
        lbl_ip.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 0))
        self.entry_ip = ctk.CTkEntry(net_frame, font=self.font_entry, fg_color="#0a1015", border_color=BORDER_DARK, corner_radius=0, text_color=ACCENT)
        self.entry_ip.insert(0, "1.1.1.1")
        self.entry_ip.grid(row=1, column=0, sticky="ew", padx=15, pady=(5, 15))

        lbl_port = ctk.CTkLabel(net_frame, text=LANG[self.current_lang]['lbl_port'], font=self.font_label, text_color=TEXT_MAIN)
        lbl_port.grid(row=0, column=1, sticky="w", padx=15, pady=(15, 0))
        self.entry_port = ctk.CTkEntry(net_frame, font=self.font_entry, fg_color="#0a1015", border_color=BORDER_DARK, corner_radius=0, text_color=ACCENT)
        self.entry_port.insert(0, "443")
        self.entry_port.grid(row=1, column=1, sticky="ew", padx=15, pady=(5, 15))

        lbl_sni = ctk.CTkLabel(net_frame, text=LANG[self.current_lang]['lbl_sni'], font=self.font_label, text_color=TEXT_MAIN)
        lbl_sni.grid(row=0, column=2, sticky="w", padx=15, pady=(15, 0))
        self.entry_sni = ctk.CTkEntry(net_frame, font=self.font_entry, fg_color="#0a1015", border_color=BORDER_DARK, corner_radius=0, text_color=ACCENT, placeholder_text="")
        self.entry_sni.grid(row=1, column=2, sticky="ew", padx=15, pady=(5, 15))

        self.btn_analyze = ctk.CTkButton(net_frame, text=LANG[self.current_lang]['btn_analyze'],
                                         fg_color="transparent", border_width=1, border_color=ACCENT, text_color=ACCENT,
                                         hover_color="#003322", corner_radius=0, font=self.font_label,
                                         command=self.start_analysis)
        self.btn_analyze.grid(row=1, column=3, sticky="e", padx=15, pady=(5, 15), ipadx=10)

        # --- Frame Entradas ARCHIVOS LOCALES ---
        loc_frame = ctk.CTkFrame(main_container, fg_color=BG_FRAME, border_width=1, border_color=BORDER_DARK, corner_radius=0)
        loc_frame.pack(fill="x", pady=(0, 15))
        
        lbl_loc = ctk.CTkLabel(loc_frame, text=LANG[self.current_lang]['lbl_local_mode'], font=self.font_label, text_color=TEXT_MAIN)
        lbl_loc.pack(anchor="w", padx=15, pady=(10, 0))

        # FILA 1: Cargar Archivos
        loc_btn_frame = ctk.CTkFrame(loc_frame, fg_color="transparent")
        loc_btn_frame.pack(fill="x", padx=15, pady=(10, 5))
        
        btn_opts = {'fg_color': "#131f28", 'border_width': 1, 'border_color': BORDER_DARK, 'text_color': TEXT_MAIN, 'hover_color': "#1a2b35", 'corner_radius': 0, 'font': self.font_label}

        self.btn_load_cer = ctk.CTkButton(loc_btn_frame, text=LANG[self.current_lang]['btn_load_cer'], command=self.select_certs, width=170, **btn_opts)
        self.btn_load_cer.pack(side="left")
        self.lbl_cer_path = ctk.CTkLabel(loc_btn_frame, text=LANG[self.current_lang]['no_file'], font=self.font_entry, text_color="#7a8a9a")
        self.lbl_cer_path.pack(side="left", padx=10)

        self.btn_load_key = ctk.CTkButton(loc_btn_frame, text=LANG[self.current_lang]['btn_load_key'], command=self.select_key, width=130, **btn_opts)
        self.btn_load_key.pack(side="left", padx=(20, 0))
        self.lbl_key_path = ctk.CTkLabel(loc_btn_frame, text=LANG[self.current_lang]['no_file'], font=self.font_entry, text_color="#7a8a9a")
        self.lbl_key_path.pack(side="left", padx=10)

        self.btn_verify_local = ctk.CTkButton(loc_btn_frame, text=LANG[self.current_lang]['btn_verify_local'],
                                              fg_color="transparent", border_width=1, border_color=ACCENT, text_color=ACCENT,
                                              hover_color="#003322", corner_radius=0, font=self.font_label,
                                              command=self.start_local_analysis)
        self.btn_verify_local.pack(side="right")

        # FILA 2: Herramientas Extra
        tools_frame = ctk.CTkFrame(loc_frame, fg_color="transparent")
        tools_frame.pack(fill="x", padx=15, pady=(5, 10))
        
        self.btn_clear = ctk.CTkButton(tools_frame, text=LANG[self.current_lang]['btn_clear'], command=self.clear_local_files, width=80, fg_color="#3a1111", border_width=1, border_color="#ff5555", text_color="#ff5555", hover_color="#5a1a1a", corner_radius=0, font=self.font_label)
        self.btn_clear.pack(side="left", padx=(0, 20))

        self.btn_concat = ctk.CTkButton(tools_frame, text=LANG[self.current_lang]['btn_concat'], command=self.tool_concat, width=100, **btn_opts)
        self.btn_concat.pack(side="left", padx=(0, 10))
        
        self.btn_split = ctk.CTkButton(tools_frame, text=LANG[self.current_lang]['btn_split'], command=self.tool_split, width=100, **btn_opts)
        self.btn_split.pack(side="left", padx=(0, 10))
        
        self.btn_convert = ctk.CTkButton(tools_frame, text=LANG[self.current_lang]['btn_convert'], command=self.tool_convert, width=120, **btn_opts)
        self.btn_convert.pack(side="left", padx=(0, 10))
        
        self.btn_export_p12 = ctk.CTkButton(tools_frame, text=LANG[self.current_lang]['btn_export_p12'], command=self.tool_export_p12, width=100, **btn_opts)
        self.btn_export_p12.pack(side="left")

        # --- ÁREA DE PESTAÑAS (TABVIEW) ---
        self.tabview = ctk.CTkTabview(main_container, corner_radius=0, border_width=1, border_color=BORDER_DARK,
                                      fg_color=BG_FRAME, text_color=ACCENT, 
                                      segmented_button_fg_color="#0a1015",
                                      segmented_button_selected_color=BORDER_DARK,
                                      segmented_button_unselected_color="#0a1015",
                                      segmented_button_unselected_hover_color="#131f28")
        self.tabview.pack(fill="both", expand=True)
        self.create_new_tab("Inicio")

        # --- BOTONERA INFERIOR ---
        bot_frame = ctk.CTkFrame(self, fg_color="transparent")
        bot_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        self.btn_export_certs = ctk.CTkButton(bot_frame, text=LANG[self.current_lang]['btn_export_certs'],
                                        fg_color="transparent", border_width=1, border_color=ACCENT, text_color=ACCENT,
                                        hover_color="#003322", corner_radius=0, font=self.font_label, width=200,
                                        command=self.export_tab_certs)
        self.btn_export_certs.pack(side="left")

        self.btn_export = ctk.CTkButton(bot_frame, text=LANG[self.current_lang]['btn_export'],
                                        fg_color="transparent", border_width=1, border_color=TEXT_MAIN, text_color=TEXT_MAIN,
                                        hover_color="#1a2b35", corner_radius=0, font=self.font_label, width=200,
                                        command=self.export_report)
        self.btn_export.pack(side="right")

    def toggle_language(self):
        self.current_lang = 'en' if self.current_lang == 'es' else 'es'
        self.update_texts()

    def update_texts(self):
        t = LANG[self.current_lang]
        self.btn_lang.configure(text=t['btn_lang'])
        self.btn_analyze.configure(text=t['btn_analyze'])
        self.btn_export.configure(text=t['btn_export'])
        self.btn_export_certs.configure(text=t['btn_export_certs'])
        self.btn_load_cer.configure(text=t['btn_load_cer'])
        self.btn_load_key.configure(text=t['btn_load_key'])
        self.btn_verify_local.configure(text=t['btn_verify_local'])
        self.btn_clear.configure(text=t['btn_clear'])
        self.btn_concat.configure(text=t['btn_concat'])
        self.btn_split.configure(text=t['btn_split'])
        self.btn_convert.configure(text=t['btn_convert'])
        self.btn_export_p12.configure(text=t['btn_export_p12'])
        if not self.local_cert_paths: 
            self.lbl_cer_path.configure(text=t['no_file'])
        if not self.local_key_path: 
            self.lbl_key_path.configure(text=t['no_file'])

    def sanitize_filename(self, text):
        return re.sub(r'(?u)[^-\w.]', '_', str(text).strip())

    # --- ARCHIVOS Y HERRAMIENTAS LOCALES ---
    def select_certs(self):
        paths = filedialog.askopenfilenames(filetypes=[("Certificados", "*.cer *.crt *.pem *.p7b *.p12 *.pfx"), ("Todos los Archivos", "*.*")])
        if paths:
            self.local_cert_paths = list(paths)
            if len(self.local_cert_paths) == 1:
                self.lbl_cer_path.configure(text=self.local_cert_paths[0].split('/')[-1])
            else:
                self.lbl_cer_path.configure(text=f"{len(self.local_cert_paths)} archivos selecc.")

    def select_key(self):
        path = filedialog.askopenfilename(filetypes=[("Private Keys", "*.key *.pem"), ("Todos los Archivos", "*.*")])
        if path:
            self.local_key_path = path
            self.lbl_key_path.configure(text=path.split('/')[-1])

    def clear_local_files(self):
        self.local_cert_paths = []
        self.local_key_path = None
        t = LANG[self.current_lang]
        self.lbl_cer_path.configure(text=t['no_file'])
        self.lbl_key_path.configure(text=t['no_file'])

    def tool_concat(self):
        t = LANG[self.current_lang]
        if not self.local_cert_paths:
            messagebox.showwarning("Warning", t['warn_no_cert_sel'])
            return
        
        save_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM File", "*.pem")])
        if save_path:
            try:
                with open(save_path, 'wb') as f_out:
                    for path in self.local_cert_paths:
                        with open(path, 'rb') as fc:
                            f_out.write(fc.read().strip() + b"\n")
                    
                    if self.local_key_path:
                        with open(self.local_key_path, 'rb') as fk:
                            f_out.write(fk.read().strip() + b"\n")
                            
                messagebox.showinfo("Export", t['exp_success'])
            except Exception as e:
                messagebox.showerror("Error", t['exp_err'].format(e=str(e)))

    def tool_split(self):
        t = LANG[self.current_lang]
        if not self.local_cert_paths:
            messagebox.showwarning("Warning", t['warn_no_cert_sel'])
            return

        dir_path = filedialog.askdirectory(title="Seleccionar carpeta destino para bloques extraídos")
        if dir_path:
            try:
                total_blocks = 0
                for path in self.local_cert_paths:
                    if path.lower().endswith(('.p12', '.pfx')):
                        continue
                        
                    with open(path, 'rb') as f:
                        data = f.read()
                    
                    blocks = re.findall(b"(-----BEGIN .*?-----END .*?\n?)", data, re.DOTALL)
                    if blocks:
                        base_name = path.split('/')[-1].split('.')[0]
                        for idx, block in enumerate(blocks, start=1):
                            out_name = os.path.join(dir_path, f"{base_name}_bloque_{idx}.pem")
                            with open(out_name, 'wb') as f_out:
                                f_out.write(block.strip() + b"\n")
                        total_blocks += len(blocks)
                
                if total_blocks > 0:
                    messagebox.showinfo("Split", t['msg_split_ok'].format(n=total_blocks))
                else:
                    messagebox.showinfo("Split", "No se encontraron bloques PEM de texto en los archivos.")
            except Exception as e:
                messagebox.showerror("Error", t['exp_err'].format(e=str(e)))

    def tool_convert(self):
        t = LANG[self.current_lang]
        if not self.local_cert_paths:
            messagebox.showwarning("Warning", t['warn_no_cert_sel'])
            return
            
        try:
            for path in self.local_cert_paths:
                if path.lower().endswith(('.p12', '.pfx')):
                    continue
                    
                with open(path, 'rb') as f:
                    datos = f.read()
                    
                if b"-----BEGIN CERTIFICATE-----" in datos:
                    certs = x509.load_pem_x509_certificates(datos)
                    if len(certs) == 1:
                        save_path = filedialog.asksaveasfilename(title=f"Convertir {path.split('/')[-1]} a DER", defaultextension=".cer", filetypes=[("DER Binary", "*.cer *.der")])
                        if save_path:
                            with open(save_path, 'wb') as f_out:
                                f_out.write(certs[0].public_bytes(serialization.Encoding.DER))
                            messagebox.showinfo("Convert", t['msg_conv_der'])
                    elif len(certs) > 1:
                        dir_path = filedialog.askdirectory(title=f"Archivo {path.split('/')[-1]} tiene múltiples certs: Elija carpeta para DERs")
                        if dir_path:
                            for i, cert in enumerate(certs):
                                cn = self.get_name_attribute(cert.subject, NameOID.COMMON_NAME) or f"cert_{i}"
                                safe_cn = self.sanitize_filename(cn)
                                out_name = os.path.join(dir_path, f"{i}_{safe_cn}.der")
                                with open(out_name, 'wb') as f_out:
                                    f_out.write(cert.public_bytes(serialization.Encoding.DER))
                            messagebox.showinfo("Convert", f"Se exportaron {len(certs)} archivos DER.")
                else:
                    cert = x509.load_der_x509_certificate(datos)
                    save_path = filedialog.asksaveasfilename(title=f"Convertir {path.split('/')[-1]} a PEM", defaultextension=".pem", filetypes=[("PEM Text", "*.pem *.crt")])
                    if save_path:
                        with open(save_path, 'wb') as f_out:
                            f_out.write(cert.public_bytes(serialization.Encoding.PEM))
                        messagebox.showinfo("Convert", t['msg_conv_pem'])
                        
        except Exception as e:
            messagebox.showerror("Error", t['exp_err'].format(e=str(e)))

    def tool_export_p12(self):
        t = LANG[self.current_lang]
        if not self.local_cert_paths or not self.local_key_path:
            messagebox.showwarning("Warning", t['warn_p12_needs_key'])
            return

        llave_privada = self._load_private_key_obj(self.local_key_path, t)
        if not llave_privada: return

        certificados = self._load_all_certs_obj(t)
        if not certificados: return

        bytes_pub_key = llave_privada.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        leaf_cert = None
        cas = []
        for cert in certificados:
            bytes_pub_cert = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if bytes_pub_cert == bytes_pub_key and leaf_cert is None:
                leaf_cert = cert
            else:
                cas.append(cert)

        if not leaf_cert:
            messagebox.showerror("Error", "Ninguno de los certificados seleccionados coincide con la llave privada. Imposible crear P12.")
            return

        dialog = ctk.CTkInputDialog(text=t['ask_pwd_new_p12'], title="Password P12")
        pwd = dialog.get_input()
        if pwd is None: return 
        
        if pwd == "":
            encryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(pwd.encode())

        save_path = filedialog.asksaveasfilename(defaultextension=".p12", filetypes=[("PKCS#12", "*.p12 *.pfx")])
        if save_path:
            try:
                cn = self.get_name_attribute(leaf_cert.subject, NameOID.COMMON_NAME) or "certificate"
                p12_data = pkcs12.serialize_key_and_certificates(
                    name=cn.encode('utf-8'),
                    key=llave_privada,
                    cert=leaf_cert,
                    cas=cas if cas else None,
                    encryption_algorithm=encryption
                )
                with open(save_path, 'wb') as f:
                    f.write(p12_data)
                messagebox.showinfo("Export", t['exp_success'])
            except Exception as e:
                messagebox.showerror("Error", t['exp_err'].format(e=str(e)))

    # --- AYUDANTES INTERNOS DE CRIPTOGRAFÍA ---
    def _load_private_key_obj(self, path, t):
        try:
            with open(path, 'rb') as f:
                datos = f.read()
            try:
                return serialization.load_pem_private_key(datos, password=None)
            except ValueError as e:
                if "password" in str(e).lower() or "encrypted" in str(e).lower() or b"ENCRYPTED" in datos:
                    dialog = ctk.CTkInputDialog(text=t['ask_pwd_msg'], title=t['ask_pwd_title'])
                    pwd = dialog.get_input()
                    if pwd:
                        try:
                            return serialization.load_pem_private_key(datos, password=pwd.encode())
                        except ValueError:
                            messagebox.showerror("Error", t['err_pwd'])
                return None
            except TypeError:
                try:
                    return serialization.load_der_private_key(datos, password=None)
                except Exception:
                    return None
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return None

    def _load_all_certs_obj(self, t):
        certificados = []
        for path in self.local_cert_paths:
            try:
                with open(path, 'rb') as f:
                    datos = f.read()
                
                if path.lower().endswith(('.p12', '.pfx')):
                    dialog = ctk.CTkInputDialog(text=t['ask_pwd_msg_p12'], title=t['ask_pwd_title'])
                    pwd_str = dialog.get_input()
                    pwd = pwd_str.encode() if pwd_str else None
                    _, p12_cert, p12_chain = pkcs12.load_key_and_certificates(datos, pwd)
                    if p12_cert: certificados.append(p12_cert)
                    if p12_chain: certificados.extend(p12_chain)
                elif b"-----BEGIN CERTIFICATE-----" in datos:
                    certificados.extend(x509.load_pem_x509_certificates(datos))
                else:
                    certificados.append(x509.load_der_x509_certificate(datos))
            except Exception as e:
                messagebox.showerror("Error", t['err_read_cert'].format(e=str(e)))
        return certificados

    # --- PESTAÑAS Y LOGS ---
    def create_new_tab(self, name_prefix):
        self.tab_count += 1
        if len(name_prefix) > 25: name_prefix = name_prefix[:22] + "..."
            
        tab_name = f"[{self.tab_count}] {name_prefix}"
        self.tabview.add(tab_name)
        self.tabview.set(tab_name)
        
        txt = ctk.CTkTextbox(self.tabview.tab(tab_name), fg_color="#05080a", text_color=ACCENT, font=self.font_terminal, corner_radius=0, border_width=0)
        txt.pack(fill="both", expand=True, padx=2, pady=2)
        
        self.tabs_textboxes[tab_name] = txt
        return tab_name, txt

    def log(self, message, textbox):
        textbox.insert("end", message + "\n")
        textbox.see("end")

    # --- EXPORTACIONES ---
    def export_report(self):
        t = LANG[self.current_lang]
        current_tab_name = self.tabview.get()
        if not current_tab_name: return
        
        current_txt = self.tabs_textboxes.get(current_tab_name)
        if not current_txt: return
            
        report_content = current_txt.get("1.0", "end").strip()
        if not report_content: return
            
        file_path = filedialog.asksaveasfilename(title=t['exp_title'], defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                messagebox.showinfo("Export", t['exp_success'])
            except Exception as e:
                messagebox.showerror("Error", t['exp_err'].format(e=str(e)))

    def export_tab_certs(self):
        t = LANG[self.current_lang]
        current_tab_name = self.tabview.get()
        
        data = self.tabs_cert_data.get(current_tab_name)
        if not data or not data["certs"]:
            messagebox.showwarning("Warning", t['warn_no_cert_data'])
            return
            
        dir_path = filedialog.askdirectory(title="Seleccionar carpeta para guardar archivos .PEM")
        if dir_path:
            try:
                # Extraemos y guardamos todos los certificados
                for i, cert in enumerate(data["certs"]):
                    cn = self.get_name_attribute(cert.subject, NameOID.COMMON_NAME) or f"cert_{i}"
                    safe_cn = self.sanitize_filename(cn)
                    
                    out_name = os.path.join(dir_path, f"{i}_{safe_cn}.pem")
                    with open(out_name, 'wb') as f_out:
                        f_out.write(cert.public_bytes(serialization.Encoding.PEM))
                
                msg_extra = ""
                # Si hay llave privada (por ejemplo, extraída de un .p12 local), también la exportamos
                if data.get("key"):
                    key_out = os.path.join(dir_path, "llave_privada_extraida.key")
                    with open(key_out, 'wb') as f_out:
                        f_out.write(data["key"].private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
                    msg_extra = "\n\nTambién se extrajo la llave privada."

                messagebox.showinfo("Export", t['exp_success'] + msg_extra)
            except Exception as e:
                messagebox.showerror("Error", t['exp_err'].format(e=str(e)))

    # --- ANÁLISIS LOCAL Y DE RED ---
    def start_local_analysis(self):
        t = LANG[self.current_lang]
        if not self.local_cert_paths:
            messagebox.showwarning("Warning", t['warn_no_cert_sel'])
            return
            
        if len(self.local_cert_paths) == 1:
            file_name = self.local_cert_paths[0].split('/')[-1]
        else:
            file_name = f"Lote de {len(self.local_cert_paths)} archivos"
            
        tab_name, txt = self.create_new_tab(f"LOC: {file_name}")
        self.log(t['local_hdr'], txt)
        
        llave_privada = None
        certificados = []

        for path in self.local_cert_paths:
            try:
                with open(path, 'rb') as f:
                    datos_cert = f.read()
                    
                if path.lower().endswith(('.p12', '.pfx')):
                    dialog = ctk.CTkInputDialog(text=t['ask_pwd_msg_p12'], title=t['ask_pwd_title'])
                    pwd_str = dialog.get_input()
                    pwd = pwd_str.encode() if pwd_str else None
                    
                    p12_key, p12_cert, p12_chain = pkcs12.load_key_and_certificates(datos_cert, pwd)
                    if p12_cert:
                        certificados.append(p12_cert)
                    if p12_chain:
                        certificados.extend(p12_chain)
                    if p12_key:
                        llave_privada = p12_key
                        self.log("[i] Llave privada encontrada dentro del archivo P12.\n", txt)
                        
                elif b"-----BEGIN CERTIFICATE-----" in datos_cert:
                    certificados.extend(x509.load_pem_x509_certificates(datos_cert))
                else:
                    certificados.append(x509.load_der_x509_certificate(datos_cert))
            except Exception as e:
                self.log(t['err_read_cert'].format(e=str(e)), txt)
                return

        self.log(t['chain_hdr'].format(count=len(certificados)), txt)
        for i, cert in enumerate(certificados, start=1):
            subject_cn = self.get_name_attribute(cert.subject, NameOID.COMMON_NAME) or "Desconocido"
            issuer_cn = self.get_name_attribute(cert.issuer, NameOID.COMMON_NAME) or "Desconocido"
            self.log(f"[{i}] {subject_cn}", txt)
            self.log(f"    - {t['issuer']}: {issuer_cn}", txt)
            self.log(f"    - {t['valid_from']}: {cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}", txt)
            self.log(f"    - {t['valid_to']}: {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}", txt)
            self.log("", txt)

        if self.local_key_path:
            llave_privada = self._load_private_key_obj(self.local_key_path, t)

        if llave_privada and certificados:
            try:
                bytes_pub_key = llave_privada.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                match_found = False
                for i, cert in enumerate(certificados, start=1):
                    bytes_pub_cert = cert.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    if bytes_pub_cert == bytes_pub_key:
                        self.log("-" * 60, txt)
                        self.log(t['match_ok'].format(idx=i), txt)
                        match_found = True
                        break
                        
                if not match_found:
                    self.log("-" * 60, txt)
                    self.log(t['match_fail'], txt)
            except Exception as e:
                self.log(f"[-] Error al verificar la llave: {e}", txt)

        # Guardamos en memoria para poder exportarlos luego si el usuario presiona el botón inferior
        self.tabs_cert_data[tab_name] = {"certs": certificados, "key": llave_privada}

    def start_analysis(self):
        self.btn_analyze.configure(state="disabled")
        
        ip = self.entry_ip.get().strip()
        port = int(self.entry_port.get().strip())
        sni = self.entry_sni.get().strip()
        
        # --- NUEVA LÓGICA: Si SNI está vacío, usar el de IP/HOST ---
        if not sni:
            sni = ip
        
        # Crear Pestaña Nueva
        tab_name, txt = self.create_new_tab(sni)

        thread = threading.Thread(target=self.analyze, args=(ip, port, sni, tab_name, txt))
        thread.start()

    def get_name_attribute(self, name, oid):
        attributes = name.get_attributes_for_oid(oid)
        return attributes[0].value if attributes else None

    def analyze(self, ip, port, sni, tab_name, txt):
        t = LANG[self.current_lang]
        self.log(t['conn_start'].format(ip=ip, port=port, sni=sni), txt)
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((ip, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=sni) as ssock:
                    self.log(t['conn_ok'].format(tls=ssock.version(), cipher=ssock.cipher()[0]), txt)

                    try:
                        chain_der = ssock.get_unverified_chain()
                    except AttributeError:
                        self.log(t['err_py_ver'], txt)
                        return

                    if not chain_der:
                        self.log(t['err_no_cert'], txt)
                        return
                    
                    parsed_chain = [x509.load_der_x509_certificate(c, default_backend()) for c in chain_der]
                    self.tabs_cert_data[tab_name] = {"certs": parsed_chain, "key": None}

                    self.log(t['chain_hdr'].format(count=len(chain_der)), txt)
                    
                    for i, cert in enumerate(parsed_chain):
                        subject_cn = self.get_name_attribute(cert.subject, NameOID.COMMON_NAME) or "Desconocido"
                        issuer_cn = self.get_name_attribute(cert.issuer, NameOID.COMMON_NAME) or "Desconocido"
                        fp_hex = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

                        self.log(f"[{i}] {subject_cn}\n    - {t['issuer']}: {issuer_cn}", txt)
                        
                        if i == 0:
                            org = self.get_name_attribute(cert.subject, NameOID.ORGANIZATION_NAME)
                            country = self.get_name_attribute(cert.subject, NameOID.COUNTRY_NAME)
                            if org:
                                self.log(f"    - {t['cert_type']}: {t['type_ov'].format(org=org, country=country or 'N/A')}", txt)
                            else:
                                self.log(f"    - {t['cert_type']}: {t['type_dv']}", txt)

                        self.log(f"    - {t['valid_from']}: {cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}", txt)
                        self.log(f"    - {t['valid_to']}: {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}", txt)
                        self.log(f"    - {t['fingerprint']}: {fp_hex}", txt)

                        try:
                            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            sans = san_ext.value.get_values_for_type(x509.DNSName)
                            if sans:
                                self.log(f"    - {t['sans']}: {', '.join(sans[:5]) + (' ...' if len(sans)>5 else '')}", txt)
                        except x509.ExtensionNotFound: pass
                        
                        try:
                            aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                            ocsp_urls = [desc.access_location.value for desc in aia_ext.value if desc.access_method == x509.AuthorityInformationAccessOID.OCSP]
                            self.log(f"    - {t['ocsp']}: {', '.join(ocsp_urls)}", txt) if ocsp_urls else self.log(f"    - {t['ocsp']}: {t['ocsp_none']}", txt)
                        except x509.ExtensionNotFound:
                            self.log(f"    - {t['ocsp']}: {t['ocsp_none']}", txt)
                            
                        self.log("", txt)

                    self.log(t['diag_hdr'], txt)
                    
                    now = datetime.datetime.now(datetime.timezone.utc)
                    for i, cert in enumerate(parsed_chain):
                        cn = self.get_name_attribute(cert.subject, NameOID.COMMON_NAME) or "Desconocido"
                        if cert.not_valid_after_utc < now:
                            self.log(t['err_expired'].format(i=i, cn=cn, date=cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')), txt)
                        else:
                            delta = cert.not_valid_after_utc - now
                            if delta.days <= 30:
                                self.log(t['warn_expiring'].format(i=i, cn=cn, days=delta.days), txt)

                    chain_broken = False
                    for i in range(len(parsed_chain) - 1):
                        try:
                            parsed_chain[i].verify_directly_issued_by(parsed_chain[i+1])
                            self.log(t['ok_chain_link'].format(i=i, next_i=i+1), txt)
                        except Exception as e:
                            self.log(t['err_break'].format(i=i, next_i=i+1), txt)
                            self.log(t['err_break_iss'].format(i=i, issuer=self.get_name_attribute(parsed_chain[i].issuer, NameOID.COMMON_NAME)), txt)
                            self.log(t['err_break_sub'].format(next_i=i+1, subject=self.get_name_attribute(parsed_chain[i+1].subject, NameOID.COMMON_NAME)), txt)
                            self.log(t['err_crypto'].format(e=type(e).__name__), txt)
                            chain_broken = True
                    
                    if not chain_broken and len(parsed_chain) > 1:
                        self.log(t['ok_chain'], txt)
                    elif len(parsed_chain) == 1:
                        self.log(t['warn_missing'], txt)

                    last_cert = parsed_chain[-1]
                    last_cert_der = chain_der[-1]
                    
                    chain_text_blob = "".join([str(c.subject) for c in parsed_chain])
                    has_usertrust = "USERTrust" in chain_text_blob
                    has_r46 = "Root R46" in chain_text_blob

                    if has_r46:
                        if not has_usertrust:
                            self.log(t['compat_r46'], txt)
                    elif has_usertrust:
                        self.log(t['compat_usertrust'], txt)

                    if last_cert.subject == last_cert.issuer:
                        self.log(t['warn_root'], txt)
                        sys_context = ssl.create_default_context()
                        system_cas_der = sys_context.get_ca_certs(binary_form=True)
                        system_ca_hashes = {hashlib.sha256(ca).hexdigest() for ca in system_cas_der}
                        last_cert_hash = hashlib.sha256(last_cert_der).hexdigest()
                        
                        if last_cert_hash in system_ca_hashes:
                            self.log(t['root_trusted'], txt)
                        else:
                            self.log(t['root_untrusted'], txt)
                    else:
                        self.log(t['ok_root'], txt)

                    self.log(t['hsts_hdr'], txt)
                    try:
                        ssock.settimeout(3.0) 
                        http_req = f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                        ssock.sendall(http_req.encode('utf-8'))
                        
                        response_bytes = ssock.recv(4096)
                        response_str = response_bytes.decode('utf-8', errors='ignore')
                        
                        if response_str.startswith("HTTP/"):
                            headers_block = response_str.split('\r\n\r\n')[0].lower()
                            hsts_value = None
                            
                            for line in headers_block.split('\r\n'):
                                if line.startswith('strict-transport-security:'):
                                    hsts_value = line.split(':', 1)[1].strip()
                                    break
                                    
                            if hsts_value:
                                self.log(t['hsts_ok'].format(val=hsts_value), txt)
                            else:
                                self.log(t['hsts_missing'], txt)
                        else:
                            self.log(t['hsts_not_http'], txt)
                    except socket.timeout:
                        self.log(t['hsts_timeout'], txt)
                    except Exception as e:
                        self.log(t['hsts_err'].format(e=str(e)), txt)

        except Exception as e:
            self.log(t['err_fatal'].format(e=str(e)), txt)
        finally:
            self.after(0, lambda: self.btn_analyze.configure(state="normal"))

if __name__ == "__main__":
    app = SSLInspectorApp()
    app.mainloop()
