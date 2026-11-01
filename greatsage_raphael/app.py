import json
from pathlib import Path
from .report import save_report
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .analysis import inspect
from .theme import COLORS, FONT, configure, RaphaelBanner

class App:
    def __init__(self, root, inventory=None):
        self.inventory=inventory
        self.capture_path=None
        self.packet_index={}
        self.root=root;self.report=None;self.events=queue.Queue();self.busy=False;self.cancel=threading.Event()
        c=COLORS
        self.style=configure(root)
        root.title('GreatSage_Raphael · Network capture diagnosis')
        root.geometry('1400x940');root.minsize(1080,760)
        self._icon_photo=tk.PhotoImage(file=str(Path(__file__).parent/'assets/greatsage-raphael.png'))
        self._brand_photo=self._icon_photo.subsample(6,6)
        root.iconphoto(True,self._icon_photo)
        self.packet_total=tk.StringVar(value='—')
        self.finding_total=tk.StringVar(value='—')
        self.protocol_total=tk.StringVar(value='—')
        self.operation=tk.StringVar(value='READY')
        self.file_label=tk.StringVar(value='No capture loaded')
        menu=tk.Menu(root);file_menu=tk.Menu(menu,tearoff=False)
        file_menu.add_command(label='Open capture',command=self.open,accelerator='Ctrl+O')
        file_menu.add_command(label='Load trusted inventory',command=self.load_inventory)
        file_menu.add_command(label='Clear trusted inventory',command=self.clear_inventory)
        file_menu.add_separator();file_menu.add_command(label='Export JSON report',command=self.export,accelerator='Ctrl+S')
        file_menu.add_command(label='Exit',command=self.close)
        menu.add_cascade(label='File',menu=file_menu)
        view_menu=tk.Menu(menu,tearoff=False)
        view_menu.add_command(label='Analysis notes',command=self.show_notes)
        view_menu.add_command(label='All packets',command=self.show_all_packets)
        menu.add_cascade(label='View',menu=view_menu);root.configure(menu=menu)
        root.bind('<Control-o>',lambda event:self.open())
        root.bind('<Control-s>',lambda event:self.export())
        root.bind('<Escape>',lambda event:self.cancel.set() if self.busy else None)
        root.columnconfigure(1,weight=1);root.rowconfigure(0,weight=1)
        rail=ttk.Frame(root,style='Rail.TFrame',width=176,padding=(16,24));rail.grid(row=0,column=0,sticky='nsew');rail.pack_propagate(False)
        ttk.Label(rail,image=self._brand_photo,style='Rail.TLabel').pack(pady=(0,12))
        ttk.Label(rail,text='GREAT SAGE',style='RailTitle.TLabel',anchor='center').pack(fill='x')
        ttk.Label(rail,text='R A P H A E L',style='Rail.TLabel',anchor='center').pack(fill='x',pady=(4,28))
        ttk.Label(rail,text='WORKSPACE',style='Rail.TLabel').pack(anchor='w',pady=(0,8))
        ttk.Button(rail,text='Open capture',style='Rail.TButton',command=self.open).pack(fill='x',pady=2)
        ttk.Button(rail,text='Trusted inventory',style='Rail.TButton',command=self.load_inventory).pack(fill='x',pady=2)
        ttk.Button(rail,text='Analysis notes',style='Rail.TButton',command=self.show_notes).pack(fill='x',pady=2)
        ttk.Button(rail,text='Packet evidence',style='Rail.TButton',command=self.show_all_packets).pack(fill='x',pady=2)
        footer=ttk.Frame(rail,style='Rail.TFrame');footer.pack(side='bottom',fill='x')
        ttk.Label(footer,text='●  LOCAL PROCESSING',style='Rail.TLabel',foreground=c['green'],font=(FONT,8,'bold')).pack(anchor='w')
        ttk.Label(footer,text='PCAP / PCAPNG\nLocal file analysis',style='Rail.TLabel',font=(FONT,8),justify='left').pack(anchor='w',pady=(9,0))
        workspace=ttk.Frame(root,padding=(22,20,22,16));workspace.grid(row=0,column=1,sticky='nsew')
        top=ttk.Frame(workspace);top.pack(fill='x',pady=(0,16))
        brand=ttk.Frame(top);brand.pack(side='left')
        ttk.Label(brand,text='GreatSage_Raphael',style='Brand.TLabel').pack(anchor='w')
        ttk.Label(brand,text='Offline network diagnostics',style='Muted.TLabel',font=(FONT,9)).pack(anchor='w',pady=(4,0))
        self.open_button=ttk.Button(top,text='Open capture',style='Primary.TButton',command=self.open);self.open_button.pack(side='right')
        self.export_button=ttk.Button(top,text='Export JSON',command=self.export,state='disabled');self.export_button.pack(side='right',padx=9)
        self.cancel_button=ttk.Button(top,text='Cancel',command=self.cancel.set,state='disabled');self.cancel_button.pack(side='right')
        self.banner=RaphaelBanner(workspace);self.banner.pack(fill='x',pady=(0,14))
        stats=ttk.Frame(workspace);stats.pack(fill='x',pady=(0,12))
        for column,(label,value) in enumerate((('PACKETS',self.packet_total),('FINDINGS',self.finding_total),('PROTOCOLS',self.protocol_total))):
            stats.columnconfigure(column,weight=1)
            card=ttk.Frame(stats,style='Card.TFrame',padding=(15,8));card.grid(row=0,column=column,sticky='nsew',padx=(0,9 if column<2 else 0))
            ttk.Label(card,text=label,style='StatCaption.TLabel').pack(anchor='w')
            ttk.Label(card,textvariable=value,style='Stat.TLabel').pack(anchor='w')
        state_row=ttk.Frame(workspace);state_row.pack(fill='x')
        ttk.Label(state_row,textvariable=self.file_label,style='Section.TLabel').pack(side='left')
        ttk.Label(state_row,textvariable=self.operation,style='Section.TLabel',foreground=c['green']).pack(side='right')
        self.status=tk.StringVar(value='Open a PCAP or PCAPNG file to begin analysis.')
        status_label=ttk.Label(workspace,textvariable=self.status,style='Muted.TLabel',wraplength=1050,font=(FONT,9));status_label.pack(fill='x',pady=(6,8))
        workspace.bind('<Configure>',lambda event:status_label.configure(wraplength=max(300,event.width-50)))
        progress_frame=ttk.Frame(workspace,height=3);progress_frame.pack(fill='x',pady=(0,12));progress_frame.pack_propagate(False)
        self.progress=ttk.Progressbar(progress_frame,mode='indeterminate',maximum=100);self.progress.pack(fill='both',expand=True)
        main_pane=ttk.Panedwindow(workspace,orient='vertical');main_pane.pack(fill='both',expand=True)
        def place_panes():
            if main_pane.winfo_exists() and main_pane.winfo_height()>1:main_pane.sashpos(0,int(main_pane.winfo_height()*.66))
        root.after(150,place_panes)
        pane=ttk.Panedwindow(main_pane,orient='horizontal');main_pane.add(pane,weight=3)
        left=ttk.Frame(pane,padding=(0,0,12,0));right=ttk.Frame(pane,padding=(12,0,0,0));pane.add(left,weight=2);pane.add(right,weight=3)
        ttk.Label(left,text='FINDINGS',style='Section.TLabel').pack(anchor='w',pady=(0,10))
        self.findings=ttk.Treeview(left,columns=('severity','category'),show='tree headings',selectmode='browse',height=6)
        self.findings.heading('#0',text='Finding');self.findings.column('#0',width=285,stretch=False)
        for col,width in (('severity',85),('category',140)):
            self.findings.heading(col,text=col.title());self.findings.column(col,width=width,stretch=False)
        for severity,color in (('High',c['red']),('Medium',c['gold']),('Low',c['cyan'])):self.findings.tag_configure(severity,foreground=color)
        finding_scroll=ttk.Scrollbar(left,orient='horizontal',command=self.findings.xview);finding_scroll.pack(side='bottom',fill='x')
        finding_vertical=ttk.Scrollbar(left,orient='vertical',command=self.findings.yview);finding_vertical.pack(side='right',fill='y')
        self.findings.configure(xscrollcommand=finding_scroll.set,yscrollcommand=finding_vertical.set)
        self.findings.pack(fill='both',expand=True);self.findings.bind('<<TreeviewSelect>>',self.select)
        ttk.Label(right,text='FINDING DETAILS',style='Section.TLabel').pack(anchor='w',pady=(0,10))
        self.detail=tk.Text(right,wrap='word',font=(FONT,11),padx=18,pady=16,state='disabled',height=8,
                            background=c['surface'],foreground=c['text'],insertbackground=c['cyan'],
                            selectbackground=c['selection'],selectforeground='#e6e6e6',relief='flat',borderwidth=0,
                            highlightthickness=1,highlightbackground=c['border'],spacing1=2,spacing3=5)
        self.detail.tag_configure('title',font=(FONT,15,'bold'),foreground=c['cyan'],spacing3=10)
        self.detail.tag_configure('heading',font=(FONT,9,'bold'),foreground=c['gold'],spacing1=7)
        detail_scroll=ttk.Scrollbar(right,orient='vertical',command=self.detail.yview);detail_scroll.pack(side='right',fill='y')
        self.detail.configure(yscrollcommand=detail_scroll.set);self.detail.pack(fill='both',expand=True)
        bottom=ttk.Frame(main_pane,padding=(0,12,0,0));main_pane.add(bottom,weight=2)
        evidence_header=ttk.Frame(bottom);evidence_header.pack(fill='x',pady=(0,8))
        ttk.Label(evidence_header,text='PACKET EVIDENCE',style='Section.TLabel').pack(side='left')
        ttk.Label(evidence_header,text='  /  First 2,000 shown · double-click for metadata',style='Muted.TLabel',font=(FONT,8)).pack(side='left')
        ttk.Button(evidence_header,text='Show all packets',command=self.show_all_packets).pack(side='right')
        self.packets=ttk.Treeview(bottom,columns=('n','time','source','destination','protocol','ports'),show='headings',height=5)
        for col,label,width in (('n','Packet',65),('time','Relative time',120),('source','Source',205),('destination','Destination',205),('protocol','Protocol',95),('ports','Ports',145)):
            self.packets.heading(col,text=label);self.packets.column(col,width=width)
        self.packets.tag_configure('even',background=c['surface']);self.packets.tag_configure('odd',background=c['alternate'])
        scroll=ttk.Scrollbar(bottom,orient='vertical',command=self.packets.yview);self.packets.configure(yscrollcommand=scroll.set)
        horizontal=ttk.Scrollbar(bottom,orient='horizontal',command=self.packets.xview);horizontal.pack(side='bottom',fill='x');self.packets.configure(xscrollcommand=horizontal.set)
        scroll.pack(side='right',fill='y');self.packets.pack(fill='both',expand=True);self.packets.bind('<Double-1>',self.packet_detail)
        self.set_detail('Open a capture\n\nSelect Open capture to load a PCAP or PCAPNG file.\n\nANALYSIS\nSelect a finding to view its explanation, likely cause, suggested fix and packet references. Double-click a packet to inspect decoded metadata.\n\nINVENTORY\nLoad an approved inventory from the File menu to check observed addresses and server identities against your configuration.\n\nLIMITATIONS\nAnalysis runs locally. Confidence describes the observation, not proof of malicious intent. No findings does not establish safety. IP fragment reassembly, encrypted DNS and DNSSEC verification are not supported.')
        root.protocol('WM_DELETE_WINDOW',self.close);root.after(100,self.poll)

    def show_notes(self):
        if self.report:self.set_detail('Analysis notes\n\n'+'\n\n'.join(self.report['warnings']))
    def show_all_packets(self):
        if self.report:self.show_packets(self.report['packets'][:2000])
    def refresh_metrics(self):
        report=self.report
        self.packet_total.set(f"{report['packet_count']:,}" if report else '—')
        self.finding_total.set(str(len(report['findings'])) if report else '—')
        self.protocol_total.set(str(len(report['protocols'])) if report else '—')
    def load_inventory(self):
        if self.busy:return
        path=filedialog.askopenfilename(filetypes=[('Trusted inventory','*.json'),('All files','*')])
        if not path:return
        from .inventory import load_inventory
        try:self.inventory=load_inventory(path)
        except (OSError,ValueError,TypeError) as exc:messagebox.showerror('Inventory error',str(exc));return
        if self.capture_path is not None:self.load_capture(self.capture_path)
        else:self.status.set('Trusted inventory loaded. Open a capture to compare it with your approved network configuration.')
    def clear_inventory(self):
        if self.busy:return
        self.inventory=None
        if self.capture_path is not None:self.load_capture(self.capture_path)
        else:self.status.set('Trusted inventory cleared.')
    def close(self):
        self.cancel.set()
        if self.busy:self.root.after(100,self.close)
        else:self.root.destroy()
    def set_detail(self,text):
        self.detail.configure(state='normal');self.detail.delete('1.0','end');self.detail.insert('end',text)
        self.detail.tag_add('title','1.0','1.end')
        for number,line in enumerate(text.splitlines(),1):
            if line in ('WHAT HAPPENED','LIKELY CAUSE','SUGGESTED NEXT STEP','PACKET NUMBERS (up to 100)','ANALYSIS','INVENTORY','LIMITATIONS'):
                self.detail.tag_add('heading',f'{number}.0',f'{number}.end')
        self.detail.configure(state='disabled')
    def open(self):
        if self.busy: return
        path = filedialog.askopenfilename(filetypes=[('Packet captures','*.pcap *.pcapng *.cap'),('All files','*')])
        if path:self.load_capture(path)
    def load_capture(self,path):
        if self.busy:return
        self.capture_path = Path(path).resolve()
        self.file_label.set(self.capture_path.name);self.operation.set('ANALYZING');self.progress.start(12)
        self.busy=True; self.cancel.clear(); self.export_button.configure(state='disabled'); self.cancel_button.configure(state='normal'); self.open_button.configure(state='disabled'); self.status.set('Analyzing capture locally…')
        def work():
            try: self.events.put(('ok',inspect(path,self.cancel,self.inventory)))
            except Exception as exc: self.events.put(('error',str(exc)))
        threading.Thread(target=work,daemon=True).start()
    def poll(self):
        try:
            kind,result=self.events.get_nowait();self.progress.stop();self.operation.set('READY'); self.busy=False; self.open_button.configure(state='normal'); self.cancel_button.configure(state='disabled')
            if kind=='ok' and self.cancel.is_set():kind,result='error','Analysis cancelled.'
            if kind.startswith('export_'):
                self.export_button.configure(state='normal')
                if kind=='export_ok': self.status.set('Report saved locally. Reports include network addresses; review before sharing.')
                else:
                    self.status.set(result)
                    if not self.cancel.is_set():messagebox.showerror('Export failed',result)
            elif kind=='error':
                self.report=None; self.findings.delete(*self.findings.get_children()); self.packets.delete(*self.packets.get_children())
                self.set_detail(result); self.status.set('Analysis cancelled.' if self.cancel.is_set() else 'Capture could not be analyzed.')
                if not self.cancel.is_set(): messagebox.showerror('Capture error',result)
            else:
                self.export_button.configure(state='normal'); self.report=result; self.packet_index={p['number']:p for p in result['packets']}; self.findings.delete(*self.findings.get_children())
                for i,f in enumerate(result['findings']): self.findings.insert('', 'end',iid=str(i),text=f['title'],values=(f['severity'],f['category']),tags=(f['severity'],))
                self.status.set(f"{result['packet_count']:,} packets · {len(result['findings'])} findings · {len(result['warnings'])} analysis notes · inventory {'on' if result['inventory_used'] else 'off'} · "+' / '.join(f'{k}: {v}' for k,v in result['protocols'].items()))
                self.set_detail('Analysis notes\n\n'+'\n\n'.join(result['warnings'])); self.show_packets(result['packets'][:2000])
            self.refresh_metrics()
        except queue.Empty: pass
        self.root.after(100,self.poll)
    def show_packets(self,packets):
        self.packets.delete(*self.packets.get_children())
        start=self.report['packets'][0]['time'] if self.report['packets'] else 0
        for p in packets:
            self.packets.insert('', 'end',iid=str(p['number']),tags=('even' if p['number']%2==0 else 'odd',),values=(p['number'],f"{p['time']-start:.6f}s",p['source'],p['destination'],p['protocol'],f"{p['sport']} → {p['dport']}" if p['sport'] or p['dport'] else ''))
    def select(self,event=None):
        selected=self.findings.selection()
        if not selected or not self.report:return
        f=self.report['findings'][int(selected[0])]
        self.set_detail(f"{f['title']}\n\n{f['category']} · {f['severity']} severity · {f['confidence']} confidence\n\nWHAT HAPPENED\n{f['explanation']}\n\nLIKELY CAUSE\n{f['cause']}\n\nSUGGESTED NEXT STEP\n{f['fix']}\n\nPACKET NUMBERS (up to 100)\n"+', '.join(map(str,f['evidence'])))
        ids=set(f['evidence']); self.show_packets([p for p in self.report['packets'] if p['number'] in ids])
    def packet_detail(self,event=None):
        selected=self.packets.selection()
        if selected and self.report:
            packet=self.packet_index.get(int(selected[0]))
            if packet:self.set_detail('Packet metadata · no raw payload\n\n'+json.dumps(packet,indent=2,ensure_ascii=True))
    def export(self):
        if self.busy:return
        if not self.report: messagebox.showinfo('Export','Analyze a capture first.'); return
        path=filedialog.asksaveasfilename(defaultextension='.json',filetypes=[('JSON report','*.json')])
        if not path:return
        if self.capture_path is not None and Path(path).resolve()==self.capture_path:
            messagebox.showerror('Export failed','Choose a different filename; the source capture must not be overwritten.');return
        report=self.report
        self.busy=True;self.cancel.clear();self.open_button.configure(state='disabled')
        self.export_button.configure(state='disabled');self.cancel_button.configure(state='normal')
        self.status.set('Saving report locally…');self.operation.set('EXPORTING');self.progress.start(12)
        def work():
            try:save_report(report,path,self.cancel);self.events.put(('export_ok',path))
            except Exception as exc:self.events.put(('export_error',str(exc)))
        threading.Thread(target=work,daemon=True).start()

def main(inventory=None,capture=None):
    root=tk.Tk(className='GreatSage_Raphael');app=App(root,inventory)
    if capture:root.after(0,lambda:app.load_capture(capture))
    root.mainloop()
