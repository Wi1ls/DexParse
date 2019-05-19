import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Copyright (c) 2019, Bongmi
 * All rights reserved
 * Author: wi1ls@bongmi.com
 */
//https://blog.csdn.net/jiangwei0910410003/article/details/50668549
public class DexObject {
  private HeaderItem headerItem = new HeaderItem();
  private StringItem[] stringItems;
  private TypeItem[] typeItems;
  private ProtoItem[] protoItems;
  private FieldItem[] fieldItems;
  private MethodItem[] methodItems;
  private ClassItem[] classItems;

  private byte[] clzBytes;
  private int index = 0;

  public DexObject(byte[] clzBytes) {
    this.clzBytes = clzBytes;
  }

  public void parse() {
    parseHeaderItem();
    parseStringItems();
    parseTypeItems();
    parseProtoItems();
    parseFieldItems();
    parseMethodItems();
    parseClassItems();
  }

  private void parseHeaderItem() {
    //parse header_item
    headerItem.magic = getValue(8);
    headerItem.checksum = getValue(4);
    headerItem.signature = getValue(20);
    headerItem.file_size = getValueLittleEdiant(4);
    headerItem.header_size = getValueLittleEdiant(4);
    headerItem.endan_tag = getValueLittleEdiant(4);
    headerItem.link_size = getValueLittleEdiant(4);
    headerItem.link_off = getValueLittleEdiant(4);
    headerItem.map_off = getValueLittleEdiant(4);
    headerItem.string_ids_size = getValueLittleEdiant(4);
    headerItem.string_ids_off = getValueLittleEdiant(4);
    headerItem.type_ids_size = getValueLittleEdiant(4);
    headerItem.type_ids_off = getValueLittleEdiant(4);
    headerItem.prote_ids_size = getValueLittleEdiant(4);
    headerItem.prote_ids_off = getValueLittleEdiant(4);
    headerItem.field_ids_size = getValueLittleEdiant(4);
    headerItem.field_ids_off = getValueLittleEdiant(4);
    headerItem.method_ids_size = getValueLittleEdiant(4);
    headerItem.method_ids_off = getValueLittleEdiant(4);
    headerItem.class_defs_size = getValueLittleEdiant(4);
    headerItem.class_defs_off = getValueLittleEdiant(4);
    headerItem.data_size = getValueLittleEdiant(4);
    headerItem.data_off = getValueLittleEdiant(4);
    System.out.println(headerItem);
  }

  private void parseStringItems() {
    System.out.println("\n解析常量池:");
    int stringIdsSize = toInteger(headerItem.string_ids_size);
    int stringIdsOff = toInteger(headerItem.string_ids_off);
    stringItems = new StringItem[stringIdsSize];
    for (int i = 0; i < stringIdsSize; i++) {
      String offset = getValueLittleEdiant(stringIdsOff + i * 4, 4);
      stringItems[i] = new StringItem();
      StringItem item = stringItems[i];
      item.indexInStringPool = i;
      item.offset = toInteger(offset);
      item.length = toInteger(toHex(clzBytes[item.offset]));
    }
    for (int i = 0; i < stringItems.length; i++) {
      StringItem item = stringItems[i];
      item.value = getValueToChar(item.offset + 1, item.length);
      System.out.print("  *");
      System.out.println(item);
    }
  }

  private void parseTypeItems() {
    System.out.println("\n开始解析 Type:");
    int typeIdsSize = toInteger(headerItem.type_ids_size);
    int typeIdsOffset = toInteger(headerItem.type_ids_off);
    typeItems = new TypeItem[typeIdsSize];
    for (int i = 0; i < typeIdsSize; i++) {
      int indexInPool = toInteger(getValueLittleEdiant(typeIdsOffset + i * 4, 4));
      TypeItem item = new TypeItem();
      item.indexInTypeItems = i;
      item.indexToStringPool = indexInPool;
      item.value = stringItems[indexInPool].value;
      typeItems[i] = item;
      System.out.print("  *");
      System.out.println(item);
    }
  }

  //method prototype
  private void parseProtoItems() {
    System.out.println("\n 开始解析 Proto:");
    int protoIdsSize = toInteger(headerItem.prote_ids_size);
    int protoIdsOffset = toInteger(headerItem.prote_ids_off);
    protoItems = new ProtoItem[protoIdsSize];
    for (int i = 0; i < protoIdsSize; i++) {
      int thisProtoStartOffset = protoIdsOffset + i * 12;
      ProtoItem protoItem = new ProtoItem();
      protoItem.protoIndexInProtos = i;
      protoItem.shortlyTypeIndex = toInteger(getValueLittleEdiant(thisProtoStartOffset, 4));
      protoItem.shortlyTypeValue = stringItems[protoItem.shortlyTypeIndex].value;
      thisProtoStartOffset += 4;
      protoItem.returnTypeIndex = toInteger(getValueLittleEdiant(thisProtoStartOffset, 4));
      protoItem.returnTypeValue = typeItems[protoItem.returnTypeIndex].value;

      thisProtoStartOffset += 4;
      protoItem.paramsIndex = toInteger(getValueLittleEdiant(thisProtoStartOffset, 4));

      if (protoItem.paramsIndex > 0) {
        protoItem.paramsSize = toInteger(getValueLittleEdiant((protoItem.paramsIndex), 4));
        int paramsStartIndex = protoItem.paramsIndex + 4;
        for (int paramIndex = 0; paramIndex < protoItem.paramsSize; paramIndex++) {
          int indexInType = toInteger(getValueLittleEdiant(paramsStartIndex, 2));
          protoItem.params.add(typeItems[indexInType].value);
          paramsStartIndex += 2;
        }
      }

      protoItems[i] = protoItem;
      System.out.print("  *");
      System.out.println(protoItem);
    }
  }

  private void parseFieldItems() {
    System.out.println();
    System.out.println("开始解析 Field");
    int fieldSize = toInteger(headerItem.field_ids_size);
    int fieldOffset = toInteger(headerItem.field_ids_off);
    fieldItems = new FieldItem[fieldSize];
    for (int i = 0; i < fieldSize; i++) {
      FieldItem fieldItem = new FieldItem();
      fieldItem.class_index = (short) toInteger(getValueLittleEdiant(fieldOffset, 2));
      fieldItem.className = typeItems[fieldItem.class_index].value;
      fieldOffset += 2;
      fieldItem.type_index = (short) toInteger(getValueLittleEdiant(fieldOffset, 2));
      fieldItem.typeName = typeItems[fieldItem.type_index].value;
      fieldOffset += 2;
      fieldItem.name_index = toInteger(getValueLittleEdiant(fieldOffset, 4));
      fieldItem.fieldName = stringItems[fieldItem.name_index].value;
      fieldOffset += 4;
      fieldItems[i] = fieldItem;
      System.out.print("  *");
      System.out.println(fieldItem);
    }
  }

  private void parseMethodItems() {
    System.out.println();
    System.out.println("开始解析 Method");
    int methodSize = toInteger(headerItem.method_ids_size);
    int methodOff = toInteger(headerItem.method_ids_off);
    methodItems = new MethodItem[methodSize];
    for (int i = 0; i < methodSize; i++) {
      MethodItem methodItem = new MethodItem();
      methodItem.indexInMethods = i;
      methodItem.class_index = (short) toInteger(getValueLittleEdiant(methodOff, 2));
      methodOff += 2;
      methodItem.proto_index = (short) toInteger(getValueLittleEdiant(methodOff, 2));
      methodOff += 2;
      methodItem.name_index = toInteger(getValueLittleEdiant(methodOff, 4));
      methodOff += 4;

      methodItem.className = typeItems[methodItem.class_index].value;
      methodItem.protoName = protoItems[methodItem.proto_index].toString();
      methodItem.methodName = stringItems[methodItem.name_index].value;
      methodItems[i] = methodItem;
      System.out.print("  *");
      System.out.println(methodItem);
    }
  }

  private void parseClassItems() {
    System.out.println();
    System.out.println("开始解析 ClassRef");
    int classSize = toInteger(headerItem.class_defs_size);
    int classOff = toInteger(headerItem.class_defs_off);
    classItems = new ClassItem[classSize];
    for (int i = 0; i < classSize; i++) {
      ClassItem classItem = new ClassItem();

      int class_index = toInteger(getValueLittleEdiant(classOff, 4));
      classOff += 4;
      classItem.class_index = class_index;
      classItem.className = typeItems[classItem.class_index].value;

      String accessFlag = getValueLittleEdiant(classOff, 4);
      classOff += 4;
      classItem.access_flags = "0x" + accessFlag;

      int superclass_index = toInteger(getValueLittleEdiant(classOff, 4));
      classOff += 4;
      classItem.superclass_index = superclass_index;
      classItem.superClassName = typeItems[classItem.superclass_index].value;
      //todo
      int interface_off = toInteger(getValueLittleEdiant(classOff, 4));
      classOff += 4;
      classItem.interface_off = interface_off;

      int source_file_index = toInteger(getValueLittleEdiant(classOff, 4));
      classOff += 4;
      classItem.source_file_index = source_file_index;
      classItem.sourceFileName = stringItems[classItem.source_file_index].value;

      //todo
      int annotations_off = toInteger(getValueLittleEdiant(classOff, 4));
      classOff += 4;
      classItem.annotations_off = annotations_off;

      //todo
      int class_data_off = toInteger(getValueLittleEdiant(classOff, 4));
      classOff += 4;
      classItem.class_data_off = class_data_off;
      parseClassData(classItem);

      //todo
      int static_value_off = toInteger(getValueLittleEdiant(classOff, 4));
      classOff += 4;
      classItem.static_value_off = static_value_off;

      System.out.print("  *");
      System.out.println(classItem);
      classItems[i] = classItem;
    }
  }

  private void parseClassData(ClassItem classItem) {
    int classDataOff = classItem.class_data_off;
    //todo 使用 uleb128 编码

    int[] static_fileds_size_uleb128 = getULEB128(classDataOff);
    classDataOff += static_fileds_size_uleb128[1];
    int[] instance_fields_size_uleb128 = getULEB128(classDataOff);
    classDataOff += instance_fields_size_uleb128[1];
    int[] direct_method_size_uleb128 = getULEB128(classDataOff);
    classDataOff += direct_method_size_uleb128[1];
    int[] virtual_methods_size_uleb128 = getULEB128(classDataOff);
    classDataOff += virtual_methods_size_uleb128[1];
    ClassItem.ClassDataItem classDataItem = new ClassItem.ClassDataItem();
    classDataItem.static_fields_size = static_fileds_size_uleb128[0];
    classDataItem.static_fields = new ClassItem.ClassDataItem.encoded_field[classDataItem.static_fields_size];
    classDataItem.instance_fields_size = instance_fields_size_uleb128[0];
    classDataItem.instance_fields = new ClassItem.ClassDataItem.encoded_field[classDataItem.instance_fields_size];
    classDataItem.direct_method_size = direct_method_size_uleb128[0];
    classDataItem.direct_methods = new ClassItem.ClassDataItem.encode_method[classDataItem.direct_method_size];
    classDataItem.virtual_method_size = virtual_methods_size_uleb128[0];
    classDataItem.virtual_methods = new ClassItem.ClassDataItem.encode_method[classDataItem.virtual_method_size];

    //解析类的静态成员变量
    for (int i = 0; i < classDataItem.static_fields_size; i++) {
      ClassItem.ClassDataItem.encoded_field encoded_field = new ClassItem.ClassDataItem.encoded_field();
      int[] encoded_field_field_idx_diff_uleb128 = getULEB128(classDataOff);
      encoded_field.field_idx_diff = encoded_field_field_idx_diff_uleb128[0];
      classDataOff += encoded_field_field_idx_diff_uleb128[1];
      int[] encoded_field_access_flag_uleb128 = getULEB128(classDataOff);
      encoded_field.access_flags = encoded_field_access_flag_uleb128[0];
      classDataOff += encoded_field_access_flag_uleb128[1];

      classDataItem.static_fields[i] = encoded_field;
    }
    //解析类的非静态成员变量
    for (int i = 0; i < classDataItem.instance_fields_size; i++) {
      ClassItem.ClassDataItem.encoded_field encoded_field = new ClassItem.ClassDataItem.encoded_field();
      int[] encoded_field_field_idx_diff_uleb128 = getULEB128(classDataOff);
      encoded_field.field_idx_diff = encoded_field_field_idx_diff_uleb128[0];
      classDataOff += encoded_field_field_idx_diff_uleb128[1];
      int[] encoded_field_access_flag_uleb128 = getULEB128(classDataOff);
      encoded_field.access_flags = encoded_field_access_flag_uleb128[0];
      classDataOff += encoded_field_access_flag_uleb128[1];

      classDataItem.instance_fields[i] = encoded_field;
    }
    //解析非虚函数
    for (int i = 0; i < classDataItem.direct_method_size; i++) {
      ClassItem.ClassDataItem.encode_method encode_method = new ClassItem.ClassDataItem.encode_method();
      int[] encode_method_idx_diff_uleb128 = getULEB128(classDataOff);
      encode_method.method_idx_diff = encode_method_idx_diff_uleb128[0];
      classDataOff += encode_method_idx_diff_uleb128[1];

      int[] encode_method_access_flag_uleb128 = getULEB128(classDataOff);
      encode_method.access_flag = encode_method_access_flag_uleb128[0];
      classDataOff += encode_method_access_flag_uleb128[1];

      int[] encode_method_code_off_uleb128 = getULEB128(classDataOff);
      encode_method.code_off = encode_method_code_off_uleb128[0];
      classDataOff += encode_method_code_off_uleb128[1];

      classDataItem.direct_methods[i] = encode_method;
      parseCodeItem(encode_method);
    }
    //解析虚函数
    for (int i = 0; i < classDataItem.virtual_method_size; i++) {
      ClassItem.ClassDataItem.encode_method encode_method = new ClassItem.ClassDataItem.encode_method();
      int[] encode_method_idx_diff_uleb128 = getULEB128(classDataOff);
      encode_method.method_idx_diff = encode_method_idx_diff_uleb128[0];
      classDataOff += encode_method_idx_diff_uleb128[1];

      int[] encode_method_access_flag_uleb128 = getULEB128(classDataOff);
      encode_method.access_flag = encode_method_access_flag_uleb128[0];
      classDataOff += encode_method_access_flag_uleb128[1];

      int[] encode_method_code_off_uleb128 = getULEB128(classDataOff);
      encode_method.code_off = encode_method_code_off_uleb128[0];
      classDataOff += encode_method_code_off_uleb128[1];

      classDataItem.virtual_methods[i] = encode_method;
      parseCodeItem(encode_method);
    }

    classItem.classDataItem = classDataItem;

  }

  private void parseCodeItem(ClassItem.ClassDataItem.encode_method method) {
    int codeOffset = method.code_off;
    short registers_size = (short) toInteger(getValueLittleEdiant(codeOffset, 2));
    codeOffset += 2;
    short ins_size = (short) toInteger(getValueLittleEdiant(codeOffset, 2));
    codeOffset += 2;
    short outs_size = (short) toInteger(getValueLittleEdiant(codeOffset, 2));
    codeOffset += 2;
    short tries_size = (short) toInteger(getValueLittleEdiant(codeOffset, 2));
    codeOffset += 2;
    int debug_info_off = toInteger(getValueLittleEdiant(codeOffset, 4));
    codeOffset += 4;
    int insns_size = toInteger(getValueLittleEdiant(codeOffset, 4));
    codeOffset += 4;
    short[] insns = new short[insns_size];
    String[] codeBinary=new String[insns_size];
    for (int i = 0; i < insns_size; i++) {
      insns[i] = (short) toInteger(getValue(codeOffset, 2));
      codeBinary[i]="0x"+getValue(codeOffset, 2);
      codeOffset += 2;
    }
    short padding= (short) toInteger(getValueLittleEdiant(codeOffset, 2));
    codeOffset += 2;

//    try_item[] tries 和 encoded_catch_handler_list 就先不解析了

    ClassItem.ClassDataItem.encode_method.Code_item code_item=new ClassItem.ClassDataItem.encode_method.Code_item();
    code_item.registers_size=registers_size;
    code_item.ins_size=ins_size;
    code_item.outs_size=outs_size;
    code_item.tries_size=tries_size;
    code_item.debug_info_off=debug_info_off;
    code_item.insns_size=insns_size;
    code_item.insns=insns;
    code_item.codeBinary=codeBinary;

    method.code_item=code_item;
  }

  private String getValue(int length) {
    StringBuffer valueBuffer = new StringBuffer();
    for (int i = 0; i < length; i++) {
      valueBuffer.append(toHex(clzBytes[index++]));
    }
    return valueBuffer.toString();
  }

  private String getValue(int start, int length) {
    StringBuffer valueBuffer = new StringBuffer();
    for (int i = 0, startIndex = start; i < length; i++) {
      valueBuffer.append(toHex(clzBytes[startIndex++]));
    }
    return valueBuffer.toString();
  }

  private String getValueToChar(int start, int length) {
    StringBuffer valueBuffer = new StringBuffer();
    for (int i = 0, startIndex = start; i < length; i++) {
      valueBuffer.append((char) (clzBytes[startIndex++]));
    }
    return valueBuffer.toString();
  }

  //小端 因此需要向前追加
  private String getValueLittleEdiant(int length) {
    StringBuffer valueBuffer = new StringBuffer();
    for (int i = 0; i < length; i++) {
      valueBuffer.insert(0, toHex(clzBytes[index++]));
    }
    return valueBuffer.toString();
  }

  //小端 因此需要向前追加
  private String getValueLittleEdiant(int start, int length) {
    StringBuffer valueBuffer = new StringBuffer();
    for (int i = 0, startIndex = start; i < length; i++) {
      valueBuffer.insert(0, toHex(clzBytes[startIndex++]));
    }
    return valueBuffer.toString();
  }

  private String toHex(byte data) {
    String hex = String.format("%x", data);
    return hex.length() == 1 ? "0" + hex : hex;
  }

  private long toInteger(int length) {
    return Long.valueOf(getValue(length), 16);
  }

  private int toInteger(String buffer) {
    return Integer.valueOf(buffer, 16);
  }


  private int[] getULEB128(int startOffset) {
    //第一个字节
    int result = toInteger(getValue(startOffset, 1));
    startOffset++;
    int length = 1;
    if (result > 0x7f) {
      //去掉最高位
      result = result & 0x7f;
      //第一位大于 0x7f 因此要加上第二个字节的值
      //第二个字节
      int result2 = toInteger(getValue(startOffset, 1));
      startOffset++;
      //先加上第二位的
      result = ((result2 & 0x7f) << 7) + result;
      length++;
      if (result2 > 0x7f) {
        //第二个字节最高位也是 1
        //第三个字节
        int result3 = toInteger(getValue(startOffset, 1));
        startOffset++;
        result = ((result3 & 0x7f) << 14) + result;
        length++;
        if (result3 > 0x7f) {
          //计算第四个字节
          int result4 = toInteger(getValue(startOffset, 1));
          startOffset++;
          result = ((result4 & 0x7f) << 21) + result;
          length++;
          if (result4 > 0x7f) {
            //计算第五个字节，最多了
            int result5 = toInteger(getValue(startOffset, 1));
            startOffset++;
            result = ((result5 & 0x7f) << 28) + result;
            length++;
            if (result5 > 0x7f) {
              throw new RuntimeException("校验错误，第五个字节大于 0x7f");
            }
          }
        }
      }
    }
    return new int[]{result, length};
  }


  public static DexObject readClass(String path) {
    try {

      BufferedInputStream in = new BufferedInputStream(
          new FileInputStream(path));
      ByteArrayOutputStream out = new ByteArrayOutputStream(1024);

      byte[] temp = new byte[1024];
      int size = 0;
      while ((size = in.read(temp)) != -1) {
        out.write(temp, 0, size);
      }
      in.close();
      return new DexObject(out.toByteArray());
    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }


  static class HeaderItem {
    String magic;
    String checksum;
    String signature;
    String file_size;
    String header_size;
    String endan_tag;
    String link_size;
    String link_off;
    String map_off;
    String string_ids_size;
    String string_ids_off;
    String type_ids_size;
    String type_ids_off;
    String prote_ids_size;
    String prote_ids_off;
    String field_ids_size;
    String field_ids_off;
    String method_ids_size;
    String method_ids_off;
    String class_defs_size;
    String class_defs_off;
    String data_size;
    String data_off;

    @Override
    public String toString() {
      return "HeaderItem{" +
          "magic='" + magic + '\'' +
          ", \nchecksum='" + checksum + '\'' +
          ", \nsignature='" + signature + '\'' +
          ", \nfile_size='" + file_size + '\'' +
          ", \nheader_size='" + header_size + '\'' +
          ", \nendan_tag='" + endan_tag + '\'' +
          ", \nlink_size='" + link_size + '\'' +
          ", \nlink_off='" + link_off + '\'' +
          ", \nmap_off='" + map_off + '\'' +
          ", \nstring_ids_size='" + string_ids_size + '\'' +
          ", \nstring_ids_off='" + string_ids_off + '\'' +
          ", \ntype_ids_size='" + type_ids_size + '\'' +
          ", \ntype_ids_off='" + type_ids_off + '\'' +
          ", \nprote_ids_size='" + prote_ids_size + '\'' +
          ", \nprote_ids_off='" + prote_ids_off + '\'' +
          ", \nfield_ids_size='" + field_ids_size + '\'' +
          ", \nfield_ids_off='" + field_ids_off + '\'' +
          ", \nmethod_ids_size='" + method_ids_size + '\'' +
          ", \nmethod_ids_off='" + method_ids_off + '\'' +
          ", \nclass_defs_size='" + class_defs_size + '\'' +
          ", \nclass_defs_off='" + class_defs_off + '\'' +
          ", \ndata_size='" + data_size + '\'' +
          ", \ndata_off='" + data_off + '\'' +
          '}';
    }
  }

  static class StringItem {
    int indexInStringPool;
    int offset;
    int length;
    String value;

    @Override
    public String toString() {
      return "#" + indexInStringPool + ":" + value;
    }
  }

  static class TypeItem {
    int indexInTypeItems;
    int indexToStringPool;
    String value;

    @Override
    public String toString() {
      return "第" + indexInTypeItems + "号 Type,对应 #" + indexToStringPool + ",value=" + value;
    }
  }

  static class ProtoItem {
    int protoIndexInProtos;
    int shortlyTypeIndex;
    String shortlyTypeValue;
    int returnTypeIndex;
    String returnTypeValue;
    int paramsIndex;
    int paramsSize;
    List<String> params = new ArrayList<>();

    @Override
    public String toString() {
      return "shortly:" + shortlyTypeValue + ",returnTypeValue:" + returnTypeValue
          + ",paramsIndex:" + paramsIndex + ",paramsSize:" + paramsSize
          + ",params=" + params;
    }
  }

  static class FieldItem {
    short class_index;
    short type_index;
    int name_index;
    String className;
    String typeName;
    String fieldName;

    @Override
    public String toString() {
      return "FieldItem{" +
          "class_index=" + class_index +
          ", type_index=" + type_index +
          ", name_index=" + name_index +
          ", className='" + className + '\'' +
          ", typeName='" + typeName + '\'' +
          ", fieldName='" + fieldName + '\'' +
          '}';
    }
  }

  static class MethodItem {
    int indexInMethods;
    short class_index;
    String className;
    short proto_index;
    String protoName;
    int name_index;
    String methodName;


    @Override
    public String toString() {
      return "MethodItem{" +
          "className='" + className + '\'' +
          ", protoName='" + protoName + '\'' +
          ", methodName='" + methodName + '\'' +
          '}';
    }
  }


  static class ClassItem {
    int class_index;
    String className;
    String access_flags;
    int superclass_index;
    String superClassName;
    int interface_off;
    int source_file_index;
    String sourceFileName;
    int annotations_off;
    int class_data_off;
    int static_value_off;
    ClassDataItem classDataItem;

    @Override
    public String toString() {
      return "ClassItem{" +
          "class_index=" + class_index +
          ", className='" + className + '\'' +
          ", access_flags='" + access_flags + '\'' +
          ", superclass_index=" + superclass_index +
          ", superClassName='" + superClassName + '\'' +
          ", interface_off=" + interface_off +
          ", source_file_index=" + source_file_index +
          ", sourceFileName='" + sourceFileName + '\'' +
          ", annotations_off=" + annotations_off +
          ", class_data_off=" + class_data_off +
          ", static_value_off=" + static_value_off +
          ", classDataItem=" + classDataItem +
          '}';
    }

    static class ClassDataItem {
      //以下4 个属性都是 uleb128的
      int static_fields_size;
      int instance_fields_size;
      int direct_method_size;
      int virtual_method_size;

      encoded_field[] static_fields;
      encoded_field[] instance_fields;
      encode_method[] direct_methods;
      encode_method[] virtual_methods;

      @Override
      public String toString() {
        return "\n    *ClassDataItem{" +
            "static_fields_size=" + static_fields_size +
            ", instance_fields_size=" + instance_fields_size +
            ", direct_method_size=" + direct_method_size +
            ", virtual_method_size=" + virtual_method_size +
            ", \n   *static_fields=" + Arrays.toString(static_fields) +
            ", \n   *instance_fields=" + Arrays.toString(instance_fields) +
            ", \n   *direct_methods=" + Arrays.toString(direct_methods) +
            ", \n   *virtual_methods=" + Arrays.toString(virtual_methods) +
            '}';
      }

      static class encoded_field {
        //以下属性是 uleb128的
        int field_idx_diff;
        int access_flags;

        @Override
        public String toString() {
          return "\n      *encoded_field{" +
              "field_idx_diff=" + field_idx_diff +
              ", access_flags=" + String.format("0x%x", access_flags) +
              '}';
        }
      }

      static class encode_method {
        //以下属性也是 uleb128
        int method_idx_diff;
        int access_flag;
        //指向 code_item
        int code_off;

        //根据 code_off 产生的
        Code_item code_item;

        @Override
        public String toString() {
          return "\nencode_method{" +
              "method_idx_diff=" + method_idx_diff +
              ", access_flag=" + access_flag +
              ", code_off=" + code_off +
              ",\n           code_item=" + code_item +
              '}';
        }

        //padding在需要对齐时；tries、handlers在确有 try 语句时存在
        static class Code_item {
          //函数需要的寄存器数量
          short registers_size;
          //输入参数所占空间，单位为 双字节
          short ins_size;
          //内部调用其他函数时，所需参数占用的空间，单位为 双字节
          short outs_size;
          //函数内部 try 语句块相关信息
          short tries_size;
          int debug_info_off;

          //指令码数组长度和指令码的内容
          //Dex 文件中指令码长度为 2 字节
          int insns_size;
          short[] insns;

          //根据 insns 自己写的，不在 dex 文件内的
          String[] codeBinary;

          //对 tries 数组进行字节对齐
          short padding;
          //try 语句相关信息，若 trise_size 为-，则不含
          Try_item[] tries;
          //catch 语句对应的内容
          Encoded_catch_handler_list handler;

          @Override
          public String toString() {
            return "\n                *Code_item{" +
                "\nregisters_size(寄存器个数)=" + registers_size +
                ", ins_size(入参空间)=" + ins_size +
                ", outs_size(内部函数调用空间)=" + outs_size +
                ", tries_size(try 语句块数量)=" + tries_size +
                ", debug_info_off=" + debug_info_off +
                ", insns_size(指令数组)=" + insns_size +
                ", insns(指令)=" + Arrays.toString(insns) +
                ", \ncodeBinary="+Arrays.toString(codeBinary)+
                ", padding(try 语句块对齐)=" + padding +
                ", tries，handler先不解析";
          }

          static class Try_item {
            int start_addr;
            short insn_count;
            short handler_off;
          }

          static class Encoded_catch_handler_list {
            //uleb128
            int handlers_size;
            Encoded_catch_handler[] list;

            static class Encoded_catch_handler {
              //sleb128
              int size;
              Encoded_type_addr_pair[] handlers;
              //uleb128
              int catch_all_addr;

              static class Encoded_type_addr_pair {
                //uleb128
                int type_index;
                int addr;
              }
            }
          }


        }
      }
    }
  }

}
