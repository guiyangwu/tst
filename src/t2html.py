#!/usr/bin/env python3

#  Copyright 2015 GuiYang WU
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

'''
Convert .t file to HTML web page.
t2html.py <XX.t> XX.html
'''

def convert(): mlc = False 
    max_width = 180
    print_table_start()
    color = "lightyellow"
    while True:
        try:
            line = input()
            line = line.strip()
            if line == "":
                print("<tr bgcolor='white'><td colspan=3>&nbsp;</td></tr>")
                continue
            if line != "" and line[0] == "#":
                print("<tr bgcolor='DeepSkyBlue'><td colspan=3>" + line + "</td></tr>")
                continue
            if mlc == True:
                print("<tr bgcolor='CornflowerBlue'><td colspan=3>" + line + "</td></tr>")
                if line in ["'''", '"""']:
                    mlc = False
                continue
            else:
                if line in ["'''", '"""']:
                    print("<tr bgcolor='CornflowerBlue'><td colspan=3>" + line + "</td></tr>")
                    mlc = True
                    continue
            print_table_row(line, color, max_width)
        except EOFError:
            break
    print_table_end()
 
def print_table_start():
    print("<table border='1' CELLPADDING='0' CELLSPACING='0'>")
     
def print_table_end():
    print("</table>")
     
def print_table_row(line, color,max_width):
    fields = get_fields(line)
    if len(fields) == 0:
        print("<tr bgcolor='white'>")
    elif len(fields) > 0 and fields[0] in ["case", "procedure", "state"]:
        print("<tr bgcolor='Wheat'>")
    else:
        print("<tr bgcolor='{}'>".format(color))
    for field in fields:
        if not field:
            print("<td></td>")
        else:
            number = field.replace(",", " ")
            try:
                x = float(number)
                print("<td align='right'>{0:d}</td>".format(round(x)))
            except ValueError:
                if len(field) <= max_width:
                    field = escape_html(field)
                else:
                    field = "{0}...".format(escape_html(field[:max_width]))
                print("<td>{0}</td>".format(field))
    if len(fields) < 3:
        print("<td colspan=" + str(3 - len(fields)) + ">&nbsp;</td>")
    print("</tr>")
     
def get_fields(line):
    fields = []
    field = ""
    qt = None
    for ch in line:
        if ch in "\"":
            if qt is None:
                qt = ch
            elif qt == ch:
                qt = None
            else:
                field += ch
                continue
        if qt is None and ch == ",":
            fields.append(field)
            field = ""
        else:
            field  += ch
    if field:
        fields.append(field)
    return fields
         
def escape_html(txt):
    txt = txt.replace(">", "&gt;")
    txt = txt.replace("<", "&lt;")
    txt = txt.replace("&", "&amp;")
    return txt

if __name__ == "__main__":
    convert()
