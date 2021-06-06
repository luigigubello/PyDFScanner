import click
import sys
import pathlib
import mimetypes
import re
import zlib


def check_path(path):
    if pathlib.Path(path).is_file():
        if mimetypes.guess_type(path)[0] == 'application/pdf':
            return True
        else:
            return False


def pdf_structure(lines):
    structure = {"header": "", "obj": 0, "endobj": 0, "stream": 0, "endstream": 0, "xref": 0, "trailer": 0,
                 "startxref": 0}
    if b'%PDF-' in lines:
        version = re.search(rb'%PDF-(\d+.\d+)', lines).group(1)
        structure['header'] = '%PDF-' + str(version, 'utf-8')
    structure['obj'] = lines.count(b' obj')
    structure['endobj'] = lines.count(b'endobj')
    structure['endstream'] = lines.count(b'endstream')
    structure['stream'] = lines.count(b'stream') - structure['endstream']
    structure['xref'] = lines.count(b'xref')
    structure['trailer'] = lines.count(b'trailer')
    structure['startxref'] = lines.count(b'startxref')
    return structure


def pdf_well_formatted(structure):
    if '%PDF-' not in structure['header'] or structure['obj'] != structure['endobj'] or structure['stream'] != \
            structure['endstream']:
        return False
    else:
        return True


def pdf_scan_obj(lines):
    stream_objects = re.compile(rb'(\d+ \d+) obj(.*?)endobj', re.S)
    objects = {}
    for obj in stream_objects.findall(lines):
        obj = list(obj)
        my_obj = str(obj[0], 'utf-8')
        objects[my_obj] = {"javascript": {"/JavaScript": 0, "/JS": 0, "launchURL": 0,
                                          "loadPolicyFile": 0, "openDoc": 0,
                                          "openPlayer": 0,
                                          "submitForm": 0, "syncAnnotScan": 0},
                           "url": {"/URI": 0, "links": []},
                           "execution": {"/Launch": 0, "/Win": 0},
                           "protocol": {"ftp": 0, "file": 0, "smb": 0, "http": 0, "https": 0,
                                        "javascript": 0},
                           "encoding": {"/FlateDecode": 0, "/ASCIIHexDecode": 0, "/LZWDecode": 0,
                                        "/JBIG2Decode": 0}}
        stream_flatdecode = re.compile(rb'.*?FlateDecode.*?stream(.*?)endstream', re.S)
        # Try to decode FlateDecode
        for item in stream_flatdecode.findall(obj[1]):
            item1 = item.strip(b'\r\n')
            try:
                item1 = zlib.decompress(item1)
                obj[1] = obj[1].replace(b'stream' + item + b'endstream', bytes(item1))
            except:
                obj[1] = obj[1].replace(b'stream' + item + b'endstream', b'\x00')
        objects[my_obj]['javascript']['/JavaScript'] = obj[1].count(b'/JavaScript')
        objects[my_obj]['javascript']['/JS'] = obj[1].count(b'/JS')
        objects[my_obj]['javascript']['launchURL'] = obj[1].count(b'.launchURL')
        objects[my_obj]['javascript']['loadPolicyFile'] = obj[1].count(b'.loadPolicyFile')
        objects[my_obj]['javascript']['openDoc'] = obj[1].count(b'.openDoc')
        objects[my_obj]['javascript']['openPlayer'] = obj[1].count(b'.openPlayer')
        objects[my_obj]['javascript']['submitForm'] = obj[1].count(b'.submitForm')
        objects[my_obj]['javascript']['syncAnnotScan'] = obj[1].count(b'.syncAnnotScan')
        stream_uri = re.compile(rb'.*?/S.*?/URI.*?/URI.*?\((.*?)\)', re.S)
        objects[my_obj]['url']['/URI'] = len(stream_uri.findall(obj[1]))
        for uri in stream_uri.findall(obj[1]):
            objects[my_obj]['url']['links'].append(str(uri, 'utf-8'))
        objects[my_obj]['execution']['/Launch'] = obj[1].count(b'/Launch')
        if objects[my_obj]['execution']['/Launch'] != 0:
            objects[my_obj]['execution']['/Win'] = obj[1].count(b'/Win')
        objects[my_obj]['protocol']['ftp'] = obj[1].count(b'ftp:')
        objects[my_obj]['protocol']['file'] = obj[1].count(b'file:')
        objects[my_obj]['protocol']['smb'] = obj[1].count(b'smb:')
        objects[my_obj]['protocol']['http'] = obj[1].count(b'http:')
        objects[my_obj]['protocol']['https'] = obj[1].count(b'https:')
        objects[my_obj]['protocol']['javascript'] = obj[1].count(b'javascript:')
        objects[my_obj]['encoding']['/FlateDecode'] = obj[1].count(b'/FlateDecode')
        objects[my_obj]['encoding']['/ASCIIHexDecode'] = obj[1].count(b'/ASCIIHexDecode')
        objects[my_obj]['encoding']['/LZWDecode'] = obj[1].count(b'/LZWDecode')
        objects[my_obj]['encoding']['/JBIG2Decode'] = obj[1].count(b'/JBIG2Decode')
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
@click.option('--force', '-f', 'force', is_flag=True, help='Optional. Force analysis in corrupted PDFs.')
def scanpdf(path, json, verbose, force):
    """
    📡 PyDF Scanner - https://github.com/luigigubello/PyDFScanner
    """
    if not check_path(path):
        print("Wrong filepath or mimetype.")
        sys.exit(0)
    with open(path, 'rb') as f:
        lines = f.read()
        structure = pdf_structure(lines)
        well_formatted = pdf_well_formatted(structure)
        if not well_formatted and not force:
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