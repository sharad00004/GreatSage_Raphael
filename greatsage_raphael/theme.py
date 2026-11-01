"""Defines the application palette and abstract header graphic."""
import math
import tkinter as tk
from tkinter import ttk

COLORS = {
    'background': '#080e1d', 'rail': '#0c1327', 'surface': '#0f1a30',
    'raised': '#15223a', 'alternate': '#121e35', 'border': '#223650',
    'text': '#cfd5df', 'muted': '#93a2ba', 'cyan': '#78c2d5',
    'blue': '#216086', 'selection': '#204665', 'red': '#dc7482',
    'gold': '#d3bc90', 'green': '#7fc6b0',
}
FONT = 'DejaVu Sans'


def configure(root):
    c=COLORS
    root.configure(background=c['background'])
    root.option_add('*Menu.background',c['rail'])
    root.option_add('*Menu.foreground',c['text'])
    root.option_add('*Menu.activeBackground',c['selection'])
    root.option_add('*Menu.activeForeground',c['text'])
    style=ttk.Style(root);style.theme_use('clam')
    style.configure('.',background=c['background'],foreground=c['text'],font=(FONT,10),bordercolor=c['border'])
    style.configure('TFrame',background=c['background'])
    style.configure('Rail.TFrame',background=c['rail'])
    style.configure('Card.TFrame',background=c['surface'])
    style.configure('TLabel',background=c['background'],foreground=c['text'])
    style.configure('Muted.TLabel',foreground=c['muted'])
    style.configure('Brand.TLabel',font=(FONT,20,'bold'),foreground=c['text'])
    style.configure('Section.TLabel',font=(FONT,10,'bold'),foreground=c['cyan'])
    style.configure('Rail.TLabel',background=c['rail'],foreground=c['muted'])
    style.configure('RailTitle.TLabel',background=c['rail'],foreground=c['cyan'],font=(FONT,13,'bold'))
    style.configure('Stat.TLabel',background=c['surface'],foreground=c['text'],font=(FONT,20,'bold'))
    style.configure('StatCaption.TLabel',background=c['surface'],foreground=c['muted'],font=(FONT,9))
    style.configure('TButton',background=c['raised'],foreground=c['text'],padding=(14,9),borderwidth=1,relief='flat')
    style.map('TButton',background=[('disabled',c['surface']),('active',c['selection'])],foreground=[('disabled','#5e6f89')])
    style.configure('Primary.TButton',background=c['blue'],foreground='#e6e6e6',font=(FONT,10,'bold'))
    style.map('Primary.TButton',background=[('disabled',c['surface']),('active','#2d77a0')])
    style.configure('Rail.TButton',background=c['rail'],foreground=c['text'],padding=(10,11),anchor='w')
    style.map('Rail.TButton',background=[('active',c['raised'])])
    style.configure('Treeview',background=c['surface'],fieldbackground=c['surface'],foreground=c['text'],rowheight=30,borderwidth=0,font=(FONT,10))
    style.map('Treeview',background=[('selected',c['selection'])],foreground=[('selected','#e6e6e6')])
    style.configure('Treeview.Heading',background=c['raised'],foreground=c['cyan'],font=(FONT,9,'bold'),padding=(9,10),relief='flat')
    style.map('Treeview.Heading',background=[('active',c['selection'])])
    style.configure('TScrollbar',background=c['border'],troughcolor=c['background'],arrowcolor=c['muted'],borderwidth=0)
    style.map('TScrollbar',background=[('active',c['blue'])])
    style.configure('TPanedwindow',background=c['border'],sashwidth=5)
    style.configure('TSeparator',background=c['border'])
    style.configure('Horizontal.TProgressbar',background=c['cyan'],troughcolor=c['surface'],borderwidth=0,lightcolor=c['cyan'],darkcolor=c['cyan'])
    return style


class RaphaelBanner(tk.Canvas):
    """Draws the header background and geometric emblem."""
    def __init__(self,parent):
        super().__init__(parent,height=132,background=COLORS['surface'],highlightthickness=1,highlightbackground=COLORS['border'])
        self.bind('<Configure>',self.draw)
    def draw(self,event=None):
        self.delete('all');w=self.winfo_width();h=self.winfo_height()
        for x in range(0,w,34):self.create_line(x,0,x,h,fill='#14223a')
        for y in range(0,h,34):self.create_line(0,y,w,y,fill='#14223a')
        self.create_rectangle(0,0,4,h,fill=COLORS['cyan'],outline='')
        self.create_text(23,25,anchor='w',text='OFFLINE NETWORK ANALYSIS',fill=COLORS['gold'],font=(FONT,9,'bold'))
        self.create_text(23,59,anchor='w',text='Packet capture analysis',fill=COLORS['text'],font=(FONT,22,'bold'))
        self.create_text(24,96,anchor='w',text='Open a PCAP or PCAPNG file to inspect findings and packet evidence.',fill=COLORS['muted'],font=(FONT,10),width=max(220,w-280))
        x=w-112;y=61
        self.create_oval(x-83,y-27,x+83,y+27,outline='#4c2e45',width=1)
        for radius,color,width in ((52,'#38283f',6),(50,'#833d54',1),(43,'#c96c82',1),(33,'#5d3348',2),(25,'#d98b9a',1)):
            self.create_oval(x-radius,y-radius,x+radius,y+radius,outline=color,width=width)
        for i in range(12):
            angle=i*math.pi/6
            self.create_line(x+46*math.cos(angle),y+46*math.sin(angle),x+57*math.cos(angle),y+57*math.sin(angle),fill='#d38294',width=1)
        points=[]
        for i in range(6):
            angle=i*math.pi/3;points.extend((x+32*math.cos(angle),y+32*math.sin(angle)))
        self.create_polygon(points,fill='',outline='#b2617b',width=1)
        self.create_polygon(x,y-19,x+14,y,x,y+19,x-14,y,fill='#9d4b62',outline='#e6bec6',width=1)
        self.create_oval(x-4,y-4,x+4,y+4,fill='#e6ced4',outline='')
