#!/usr/bin/eny python

import xml.etree.ElementTree as etree
import textwrap
from pprint import pprint


class DataType:
    # <DataType name="BodyLen" type="int" rootType="int" numericID="9" package="eobi" size="2" description="" minValue="0" maxValue="65534" noValue="0xFFFF"/>

    int_types = {
        '1': 'INT8',
        '2': 'INT16',
        '4': 'INT32',
        '8': 'INT64'
    }

    encodings = {
        'UTCTimestamp': 'ENC_LITTLE_ENDIAN|ENC_TIME_NANOS_TIME_T'
    }

    def __init__(self, element):
        self.name = element.get("name")
        self.type = element.get("type")
        self.size = element.get("size")
        self.enc = DataType.encodings.get(self.type, 'ENC_LITTLE_ENDIAN')
        self.min_value = element.get("minValue")
        self.max_value = element.get("maxValue")
        self.valid_values = self.parse_valid_values(element)

    def parse_valid_values(self, element):
        valid_values = None
        if element.find("ValidValue") is not None:
            if self.type == "int":
                valid_values = dict()
                for value_element in element.findall("ValidValue"):
                    key = int(value_element.get("value"))
                    value = value_element.get("name")
                    valid_values[key] = value
        return valid_values


    def fieldtype(self):
        if self.type == "int":
            if int(self.min_value) < 0:
                base = "FT_U"
            else:
                base = "FT_"
            return base + DataType.int_types[self.size]
        elif self.type == "PriceType":
            return "FT_INT64"
        elif self.type == "UTCTimestamp":
            return "FT_ABSOLUTE_TIME"
        return "FT_NONE"

    def display(self):
        if self.type == "int":
            return "BASE_DEC"
        elif self.type == "PriceType":
            return "BASE_DEC"
        elif self.type == "UTCTimestamp":
            return "ABSOLUTE_TIME_ISO_DATE_LOCAL"
        return "BASE_NONE"

    def strings(self):
        if self.valid_values is not None:
            return "VALS({name}names)".format(name=self.name.lower())
        return "NULL"

    def valid_values_header(self):
        return "static const value_string {}names[] = {{".format(self.name.lower())

    def valid_value_entry(self, key, value):
        return '    {{ {}, "{}" }},'.format(key, value)

    def valid_values_footer(self):
        return "    { 0, NULL }\n};"

    def __str__(self):
        return "<#DataType name={} type={} size={} minValue={} maxValue={}>".format(
            self.name,
            self.type,
            self.size,
            self.min_value,
            self.max_value
        )

    def __repr__(self):
        return self.__str__()


class Field:
    def __init__(self, element, datatypes):
        self.name = element.get("name")
        self.hidden = element.get('hidden') == "true"
        self.offset = int(element.get("offset"))
        self.datatype = datatypes[element.get("type")]

    def __str__(self):
        return "<#Field name={} hidden={} offset={} datatype={}>".format(
            self.name,
            self.hidden,
            self.offset,
            self.datatype
        )

    def hf_identifier(self):
        return "static int hf_eobi3_{} = -1;".format(self.name.lower())

    def hf_register_info(self):
        return "\n".join((
            "    {",
            "      &hf_eobi3_{name},".format(name=self.name.lower()),
            '      {{ "{name}", "eobi3.{name}", {fieldtype}, {display}, {valid_values}, 0x0, "", HFILL }}'.format(
                name=self.name,
                fieldtype=self.datatype.fieldtype(),
                display=self.datatype.display(),
                valid_values=self.datatype.strings()
            ),
            "    },"
        ))

    def proto_tree_add(self):
        # proto_tree_add_item(tree, hf_eobi3_bodylen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        return "    proto_tree_add_item(tree, {hf}, tvb, offset, {size}, {enc});\n    offset += {size};".format(
            hf="hf_eobi3_{}".format(self.name.lower()),
            offset=self.offset,
            size=self.datatype.size,
            enc=self.datatype.enc
        )


class Message:
    def __init__(self, element):
        self.name = element.get("name")

    def dissect_function_header(self):
        return textwrap.dedent("""
            static gint dissect_{name}(tvbuff_t* tvb, proto_item* ti, gint offset)
            {{
                proto_tree *tree = proto_item_add_subtree(ti, ett_eobi3_{name});
            """.format(name=self.name.lower()))

    def dissect_function_footer(self):
        return textwrap.dedent("""
            return offset;
        }""")


class EobiDataModel:
    def __init__(self):
        self.datatypes = dict()
        self.fields = dict()

    def parse(self, filename):
        tree = etree.parse('eobi.xml')
        model = tree.getroot()

        self.parse_datatypes(model)
        self.print_value_strings()

        self.parse_messages(model)
        self.print_hf_register_info()
        self.print_hf_identifiers()

    def parse_datatypes(self, root):
        for element in root.find("DataTypes").findall("DataType"):
            datatype = DataType(element)
            self.datatypes[datatype.name] = datatype

    def parse_messages(self, root):
        for element in root.find("ApplicationMessages").findall("ApplicationMessage"):
            message = Message(element)
            print(message.dissect_function_header())
            self.parse_message(element)
            print(message.dissect_function_footer())

    def parse_message(self, root):
        for element in root.iter("Member"):
            field = Field(element, self.datatypes)
            if field.name not in self.fields:
                self.fields[field.name] = field
            if not field.hidden:
                #print(field)
                print(field.proto_tree_add())

    def print_value_strings(self):
        for _, datatype in self.datatypes.iteritems():
            if datatype.valid_values is not None:
                print(datatype.valid_values_header())
                for key, value in datatype.valid_values.iteritems():
                    print(datatype.valid_value_entry(key, value))
                print(datatype.valid_values_footer())

    def print_hf_register_info(self):
        for _, field in self.fields.iteritems():
            print(field.hf_register_info())

    def print_hf_identifiers(self):
        for _, field in self.fields.iteritems():
            print(field.hf_identifier())

def main():
    datamodel = EobiDataModel()
    datamodel.parse("eobi.xml")

if __name__ == "__main__":
    main()
