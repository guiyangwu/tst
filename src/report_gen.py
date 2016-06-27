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
Convert test result .csv file into HTML web page.
report_gen.py result.csv result.html
'''

pass_count = 0
fail_count = 0

def main():
    global pass_count
    global fail_count

    max_width = 100
    print_start()
    while True:
        try:
            line = input()
            if line.split(",")[-1].strip().lower() == "failed":
                color = "red"
            else:
                color = "lightgreen"
            print_line(line, color, max_width)
        except EOFError:
            print("<p>Pass Rate: " + str(100*pass_count//(pass_count+fail_count)) + "%&nbsp;&nbsp;&nbsp;&nbsp;Passed: " + str(pass_count) + "&nbsp;&nbsp;&nbsp;&nbsp;Failed: " + str(fail_count) + "</p>")
            break
    print_end()
 
def print_start():
    print("<table border='1'>")
     
def print_end():
    print("</table>")
     
def print_line(line, color,max_width):
    global pass_count
    global fail_count

    fields = get_fields(line)
    if fields[0] == "Test":
        print("<tr bgcolor='{}'>".format("white"))
        print("<td>Test</td><td><a href=../" + fields[2] + ">" + fields[1] + "</a></td><td></td>")
        return
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
                #field = field.title()
                field = field.replace("And", "and")
                if len(field) <= max_width:
                    field = html_escape(field)
                else:
                    field = "{0}".format(html_escape(field[:max_width]))
                if field == fields[-1]:
                    print("<td><a href=log/" + fields[0] + ">" + field + "</a></td>")
                else:
                    print("<td>{0}</td>".format(field))
    if fields[-1] == "passed":
        pass_count += 1
    else:
        fail_count += 1
    print("</tr>")
     
def get_fields(line):
    fields = []
    field = ""
    quote = None
    for c in line:
        if c in "\"":
            if quote is None:
                quote = c
            elif quote == c:
                quote = None
            else:
                field += c
                continue
        if quote is None and c == ",":
            fields.append(field)
            field = ""
        else:
            field  += c
    if field:
        fields.append(field)
    return fields
         
def html_escape(text):
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text
     
main()
