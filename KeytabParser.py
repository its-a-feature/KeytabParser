#!/usr/bin/env python
# Author Cody Thomas, @its_a_feature_
# May 21, 2019
import binascii
import sys
import time
import json
import base64
# endian value of 0x01 means native byte order (version one of keytab)
# endian value of 0x02 means big-endian byte order (version two of keytab)
# Format pulled from https://www.h5l.org/manual/HEAD/krb5/krb5_fileformats.html
def usage():
    print("Usage: python2.7 keytab_extract /path/to/keytab")

def get_bytes_number(keytab, index, number, version):
    if (number*2) + index >= len(keytab):
        return 0
    if version == 1:
        #print(''.join(keytab[index:(number*2) + index])[::-2])
        return int(''.join(keytab[index:(number*2) + index])[::-2], 16)
    if version == 2:
        return int(keytab[index:(number*2) + index], 16)

def get_bytes_string(keytab, index, number):
    if (number*2) + index >= len(keytab):
        return str(0)
    return str(bytearray.fromhex(keytab[index:(number*2)+index]))

def get_bytes_key(keytab, index, number):
    if (number*2) + index >= len(keytab):
        return 0
    return base64.b64encode(bytearray.fromhex(keytab[index:(number*2)+index])).decode('utf-8')

enc_types = {
    23: "rc4-hmac",
    18: "aes256-cts-hmac-sha1-96",
    17: "aes128-cts-hmac-sha1-96",
    16: "des3-cbc-sha1-kd"
}
name_types = {
    1: "KRB5_NT_PRINCIPAL",
    2: "KRB5_NT_SRV_INST",
    5: "KRB5_NT_UID"
}


def extract_keys(keytab):
    #print(keytab)
    #keytab metadata
    i = 0
    if get_bytes_number(keytab, index=i, number=1, version=1) != 5:
        print("Keytab files start with 0x05, this isn't formatted properly")
        sys.exit()
    i += 2
    if get_bytes_number(keytab, index=i, number=1, version=1) == 2:
        version = 2
    elif get_bytes_number(keytab, index=i, number=1, version=1) == 1:
        version = 1
    else:
        print("Second byte must be 0x01 or 0x02 to indicate byte ordering for integers")
        sys.exit()
    i += 2
    entries = {}
    #int32_t size of entry
    entry_length = get_bytes_number(keytab, index=i, number=4, version=version)
    #print("entry_length: {}".format(str(entry_length)))
    #print("entry: {}".format(keytab[i: i + (entry_length*2) ]))
    i += 8
    # iterate through entries
    while entry_length != 0:
        try:
            if entry_length > 0:
                start_value = i  # start of this entry
                #uint16_t num_components
                num_components = get_bytes_number(keytab, index=i, number=2, version=version)
                
                #print("num_components: {}".format(str(num_components)))
                #print("entry_length: {}".format(str(entry_length)))
                if num_components == 0 and entry_length == 3:
                    #print("num_comp is zero, next group: {}".format(keytab[i:]))
                    continue
                i += 4
                #counted octect string realm (prefixed with 16bit length, no null terminator)
                realm_length = get_bytes_number(keytab, index=i, number=2, version=version)
                i += 4
                #print("realm_length: {}".format(str(realm_length)))
                if realm_length == 0:
                    continue
                realm = get_bytes_string(keytab, index=i, number=realm_length)
                i += realm_length * 2
                #print(realm)
                spn = ""
                for component in range(num_components):
                    component_length = get_bytes_number(keytab, index=i, number=2, version=version)
                    i += 4
                    spn += get_bytes_string(keytab, index=i, number=component_length)
                    #print("spn piece: {}".format(spn))
                    i += component_length * 2
                    spn += "/"
                spn = spn[:-1] + "@" + realm
                #print("full spn: {}".format(spn))
                #uint32_t name_type
                name_type = get_bytes_number(keytab, index=i, number=4, version=version)
                i += 8
                #print("name_type: {}".format(str(name_type)))
                #print(name_types[name_type])
                #uint32_t timestamp (time key was established)
                timestamp = get_bytes_number(keytab, index=i, number=4, version=version)
                i += 8
                #print("timestamp: {}".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))))
                #uint8_t vno8
                vno = get_bytes_number(keytab, index=i, number=1, version=version)
                i += 2
                #print("vno: {}".format(str(vno)))
                #keyblock structure: 16bit value for encryption type and then counted_octet for key
                encryption_type = get_bytes_number(keytab, index=i, number=2, version=version)
                i += 4
                #print("encryption_type: {}".format(str(encryption_type)))
                #print(enc_types[encryption_type])
                key_length = get_bytes_number(keytab, index=i, number=2, version=version)
                i += 4
                #print("key length: {}".format(str(key_length)))
                key = get_bytes_key(keytab, index=i, number=key_length)
                i += key_length * 2
                #print("key: {}".format(key))
                #uint32_t vno if >=4 bytes left in entry_length
                if entry_length > i - start_value:
                    vno = get_bytes_number(keytab, index=i, number=4, version=version)
                    i += 8
                    #print("updated vno: {}".format(str(updated_vno)))
                #uint32_t flags if >=4 bytes left in entry_length
                if entry_length > i - start_value:
                    flags = get_bytes_number(keytab, index=i, number=4, version=version)
                    i += 8
                    #print("flags: {}".format(str(flags)))
                if spn in entries:
                    entries[spn]['keys'].append({"EncType": enc_types[encryption_type], "Key": key, 'Time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp)), "KeyLength": key_length})
                else:
                    entries[spn] = {'keys': [{"EncType": enc_types[encryption_type], "Key": key, 'Time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp)), "KeyLength": key_length}]}
            else:
                i += abs(entry_length) * 2
                #print("skipping an entry")
        except Exception as e:
            print(e)
        finally:
            entry_length = get_bytes_number(keytab, index=i, number=4, version=version)
            #print("entry_length: {}".format(str(entry_length)))
            #print("entry: {}".format(keytab[i: i + (entry_length*2) ]))
            i += 8
            
    print(json.dumps(entries, indent=4, sort_keys=True))

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
        sys.exit()
    else:
        try:
            file = sys.argv[1]
            f = open(file, 'rb').read()
            keytab = str(binascii.hexlify(f))
            #print(keytab)
            extract_keys(keytab)
        except Exception as e:
            print(str(e))
            usage()
