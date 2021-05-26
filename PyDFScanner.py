import click
import sys
import pathlib
import mimetypes
import re


def check_path(path):
    if pathlib.Path(path).is_file():
        if mimetypes.guess_type(path)[0] == 'application/pdf':
            return True
        else:
            return False


def pdf_structure(lines):
    structure = {"header": "", "obj": 0, "endobj": 0, "stream": 0, "endstream": 0, "xref": 0, "trailer": 0,
                 "startxref": 0}
    if b'%PDF-' in lines[0]:
        version = re.search(rb'%PDF(.*)\n', lines[0]).group(1)
        structure['header'] = '%PDF' + str(version, 'utf-8')
    for line in lines:
        if line.endswith(b' obj\n'):
            structure['obj'] += 1
        elif line == b'endobj\n':
            structure['endobj'] += 1
        elif line == b'stream\n':
            structure['stream'] += 1
        elif line == b'endstream\n':
            structure['endstream'] += 1
        elif line == b'xref\n':
            structure['xref'] += 1
        elif line == b'trailer\n':
            structure['trailer'] += 1
        elif line == b'startxref\n':
            structure['startxref'] += 1
        else:
            continue
    return structure


def pdf_well_formatted(structure):
    if '%PDF-' not in structure['header'] or structure['obj'] != structure['endobj'] or structure['stream'] != \
            structure['endstream'] or structure['trailer'] != structure['startxref']:
        return False
    else:
        return True


def pdf_scan_obj(lines):
    objects = {}
    i = 0
    am_i_an_object = False
    current_obj = 0
    while i < len(lines):
        if lines[i].endswith(b' obj\n'):
            current_obj = str(lines[i], 'utf-8').split()[0] + ' ' + str(lines[i], 'utf-8').split()[1]
            if current_obj not in objects:
                objects[current_obj] = {"javascript": {"/JavaScript": 0, "/JS": 0, "launchURL": 0,
                                                       "loadPolicyFile": 0, "openDoc": 0,
                                                       "openPlayer": 0,
                                                       "submitForm": 0, "syncAnnotScan": 0},
                                        "url": {"/URI": 0, "links": []},
                                        "execution": {"/Launch": 0, "/Win": 0},
                                        "protocol": {"ftp": 0, "file": 0, "smb": 0, "http": 0, "https": 0,
                                                     "javascript": 0},
                                        "encoding": {"/FlateDecode": 0, "/ASCIIHexDecode": 0, "/LZWDecode": 0,
                                                     "/JBIG2Decode": 0}}
            am_i_an_object = True
        elif am_i_an_object and lines[i] != b'endobj\n':
            if b'/JavaScript' in lines[i]:
                objects[current_obj]['javascript']['/JavaScript'] += 1
            if b'/JS' in lines[i]:
                objects[current_obj]['javascript']['/JS'] += 1
            if b'.launchURL' in lines[i]:
                objects[current_obj]['javascript']['launchURL'] += 1
            if b'.loadPolicyFile' in lines[i]:
                objects[current_obj]['javascript']['loadPolicyFile'] += 1
            if b'.openDoc' in lines[i]:
                objects[current_obj]['javascript']['openDoc'] += 1
            if b'.openPlayer' in lines[i]:
                objects[current_obj]['javascript']['openPlayer'] += 1
            if b'.submitForm' in lines[i]:
                objects[current_obj]['javascript']['submitForm'] += 1
            if b'.syncAnnotScan' in lines[i]:
                objects[current_obj]['javascript']['syncAnnotScan'] += 1
            if b'/URI' in lines[i] and b'/S' not in lines[i]:
                objects[current_obj]['url']['/URI'] += 1
                try:
                    link = lines[i].split(b'/URI')[-1]
                    link = re.search(rb'\((.*?)\)', link).group(1)
                    objects[current_obj]['url']['links'].append(str(link, 'utf-8'))
                except:
                    objects[current_obj]['url']['links'].append(b'')
            if b'/Launch' in lines[i]:
                objects[current_obj]['execution']['/Launch'] += 1
            if b'/Win' in lines[i]:
                objects[current_obj]['execution']['/Win'] += 1
            if b'ftp:' in lines[i]:
                objects[current_obj]['protocol']['ftp'] += 1
            if b'file:' in lines[i]:
                objects[current_obj]['protocol']['file'] += 1
            if b'smb:' in lines[i]:
                objects[current_obj]['protocol']['smb'] += 1
            if b'http:' in lines[i]:
                objects[current_obj]['protocol']['http'] += 1
            if b'https:' in lines[i]:
                objects[current_obj]['protocol']['https'] += 1
            if b'javascript:' in lines[i]:
                objects[current_obj]['protocol']['javascript'] += 1
            if b'/FlateDecode' in lines[i]:
                objects[current_obj]['encoding']['/FlateDecode'] += 1
            if b'/ASCIIHexDecode' in lines[i]:
                objects[current_obj]['encoding']['/ASCIIHexDecode'] += 1
            if b'/LZWDecode' in lines[i]:
                objects[current_obj]['encoding']['/LZWDecode'] += 1
            if b'/JBIG2Decode' in lines[i]:
                objects[current_obj]['encoding']['/JBIG2Decode'] += 1
        elif lines[i] == b'endobj\n':
            am_i_an_object = False
        else:
            pass
        i += 1
    return objects


def beautiful_print(result):
    print(
        "/JavaScript: {}\n/JS: {}\n\tlaunchURL: {}\n\tloadPolicyFile: {}\n\topenDoc: {}\n\topenPlayer: {}\n\tsubmitForm: {}\n\tsyncAnnotScan: {}".format(
            result['javascript']['/JavaScript'], result['javascript']['/JS'],
            result['javascript']['launchURL'], result['javascript']['loadPolicyFile'],
            result['javascript']['openDoc'], result['javascript']['openPlayer'],
            result['javascript']['submitForm'], result['javascript']['syncAnnotScan']))
    print("/Launch: {}\n/Win: {}".format(result['execution']['/Launch'], result['execution']['/Win']))
    print(
        "/FlateDecode: {}\n/ASCIIHexDecode: {}\n/LZWDecode: {}\n/JBIG2Decode: {}".format(
            result['encoding']['/FlateDecode'],
            result['encoding']['/ASCIIHexDecode'],
            result['encoding']['/LZWDecode'],
            result['encoding']['/JBIG2Decode']))
    print("/URI: {}\n\tlinks: {}".format(result['url']['/URI'], result['url']['links']))
    print("Protocol:\n\tftp: {}\n\tfile: {}\n\tsmb: {}\n\thttp: {}\n\thttps: {}\n\tjavascript: {}".format(
        result['protocol']['ftp'], result['protocol']['file'], result['protocol']['smb'],
        result['protocol']['http'], result['protocol']['https'], result['protocol']['javascript']))


def result_for_human(objects, verbose):
    if not verbose:
        result = {"javascript": {"/JavaScript": 0, "/JS": 0, "launchURL": 0,
                                 "loadPolicyFile": 0, "openDoc": 0,
                                 "openPlayer": 0,
                                 "submitForm": 0, "syncAnnotScan": 0},
                  "url": {"/URI": 0, "links": []},
                  "execution": {"/Launch": 0, "/Win": 0},
                  "protocol": {"ftp": 0, "file": 0, "smb": 0, "http": 0, "https": 0,
                               "javascript": 0},
                  "encoding": {"/FlateDecode": 0, "/ASCIIHexDecode": 0, "/LZWDecode": 0,
                               "/JBIG2Decode": 0}}
        for item in objects.keys():
            for element in objects[item]['javascript'].keys():
                result['javascript'][element] += objects[item]['javascript'][element]
            for element in objects[item]['url'].keys():
                result['url'][element] += objects[item]['url'][element]
            for element in objects[item]['execution'].keys():
                result['execution'][element] += objects[item]['execution'][element]
            for element in objects[item]['protocol'].keys():
                result['protocol'][element] += objects[item]['protocol'][element]
            for element in objects[item]['encoding'].keys():
                result['encoding'][element] += objects[item]['encoding'][element]
        return result


@click.command()
@click.argument('path')
@click.option('--json', 'json', is_flag=True, help='Optional. Print JSON result.')
@click.option('--verbose', '-v', 'verbose', is_flag=True, help='Optional. Verbose mode.')
def scanpdf(path, json, verbose):
    """
    📡 PyDF Scanner - https://github.com/luigigubello/PyDFScanner
    """
    if not check_path(path):
        print("Wrong filepath or mimetype.")
        sys.exit(0)
    with open(path, 'rb') as f:
        lines = f.readlines()
        structure = pdf_structure(lines)
        well_formatted = pdf_well_formatted(structure)
        if not well_formatted:
            print("\x1b[1;33;49m" + "!! Warning:" + "\x1b[0m" + " not well-formatted document")
        else:
            if not json:
                print("Header: {}".format(structure['header']))
                print("Objects found: {}".format(structure['obj']))
                objects = pdf_scan_obj(lines)
                result = result_for_human(objects, verbose)
                if not verbose:
                    beautiful_print(result)
                else:
                    for item in objects.keys():
                        if objects[item]['javascript']['/JavaScript'] + objects[item]['javascript']['/JS'] + \
                                objects[item]['javascript']['launchURL'] + objects[item]['execution']['/Launch'] + \
                                objects[item]['protocol']['smb'] + objects[item]['protocol']['file'] + \
                                objects[item]['protocol']['javascript'] > 0:
                            print("\n\x1b[1;31;49m" + item + " obj" + "\x1b[0m")
                        else:
                            print("\n" + item + " obj")
                        beautiful_print(objects[item])
            else:
                objects = pdf_scan_obj(lines)
                result = {"structure": structure, "objects": objects}
                print(result)


if __name__ == '__main__':
    scanpdf()
