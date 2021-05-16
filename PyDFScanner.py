import click
import sys
import pathlib
import mimetypes
import re
from urllib.parse import urlparse


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
        structure['header'] = lines[0]
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
    if b'%PDF-' not in structure['header'] or structure['obj'] != structure['endobj'] or structure['stream'] != \
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
                objects[current_obj] = {"lines": [],
                                        "javascript": {"/JavaScript": 0, "/JS": 0, "launchURL": 0,
                                                       "loadPolicyFile": 0, "openDoc": 0,
                                                       "openPlayer": 0,
                                                       "submitForm": 0},
                                        "url": {"/URI": 0, "links": []},
                                        "warnings": {"potential_obfuscation": False,
                                                     "suspicious_links": False}}
            am_i_an_object = True
        elif am_i_an_object and lines[i] != b'endobj\n':
            objects[current_obj]['lines'].append(lines[i])
            if b'/JavaScript' in lines[i]:
                objects[current_obj]['javascript']['/JavaScript'] += 1
            if b'/JS' in lines[i]:
                objects[current_obj]['javascript']['/JS'] += 1
                try:
                    line = lines[i].split(b'/JS')[-1]
                    if b'(' not in line:
                        # WIP
                        objects[current_obj]['warnings']['potential_obfuscation'] = True
                except:
                    objects[current_obj]['warnings']['potential_obfuscation'] = True
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
            if b'/URI' in lines[i]:
                objects[current_obj]['url']['/URI'] += 1
                try:
                    link = lines[i].split(b'/URI')[-1]
                    if b'(' not in link or b')' not in link:
                        objects[current_obj]['url']['/URI'] -= 1
                    else:
                        # WIP
                        link = re.search(rb'\((.*?)\)', link).group(1)
                        objects[current_obj]['url']['links'].append(link)
                        scheme = urlparse(str(link, 'utf-8'))[0]
                        if scheme != 'https' and scheme != 'http':
                            objects[current_obj]['warnings']['suspicious_links'] = True
                except:
                    objects[current_obj]['url']['/URI'] -= 1
        elif lines[i] == b'endobj\n':
            am_i_an_object = False
        else:
            pass
        i += 1
    return objects


def result_for_human(objects, verbose):
    result = {"/JavaScript": 0, "/JS": 0, "launchURL": 0, "loadPolicyFile": 0, "openDoc": 0, "openPlayer": 0,
              "submitForm": 0, "/URI": 0, "links": [], "potential_obfuscation": False,
              "suspicious_links": False}
    if not verbose:
        for item in objects.keys():
            for element in objects[item]['javascript'].keys():
                result[element] += objects[item]['javascript'][element]
            for element in objects[item]['url'].keys():
                result[element] += objects[item]['url'][element]
            for element in objects[item]['warnings'].keys():
                if objects[item]['warnings'][element]:
                    result[element] = True
        return result
    else:
        verbose_result = {}
        for item in objects.keys():
            verbose_result[item] = {}
            for element in objects[item]['javascript'].keys():
                verbose_result[item][element] = objects[item]['javascript'][element]
            for element in objects[item]['url'].keys():
                verbose_result[item][element] = objects[item]['url'][element]
            for element in objects[item]['warnings'].keys():
                verbose_result[item][element] = objects[item]['warnings'][element]
        return verbose_result


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
                print("Header: {}".format(str(structure['header'], 'utf-8')[:-1]))
                print("Objects found: {}".format(structure['obj']))
                objects = pdf_scan_obj(lines)
                result = result_for_human(objects, verbose)
                if not verbose:
                    for item in result.keys():
                        if (item == 'potential_obfuscation' or item == 'suspicious_links') and result[item]:
                            print("\x1b[1;31;49m{}: {}\x1b[0m".format(item, result[item]))
                        else:
                            print("{}: {}".format(item, result[item]))
                else:
                    for item in result.keys():
                        if result[item]['potential_obfuscation'] or result[item]['suspicious_links']:
                            print("\n\x1b[1;31;49m" + item + " obj" + "\x1b[0m")
                        elif result[item]['/JavaScript'] + result[item]['/JS'] + result[item]['/URI'] > 0:
                            print("\n\x1b[1;33;49m" + item + " obj" + "\x1b[0m")
                        else:
                            print("\n" + item + " obj")
                        for element in result[item].keys():
                            print("{}: {}".format(element, result[item][element]))
            else:
                objects = pdf_scan_obj(lines)
                result = {"structure": structure, "objects": objects}
                print(result)


if __name__ == '__main__':
    scanpdf()
