/**
 * Copyright (c) 2019, Bongmi
 * All rights reserved
 * Author: wi1ls@bongmi.com
 */

public class Main {
  public static void main(String[] args) throws Exception {
    DexObject dexObject = DexObject.readClass("/Users/wi1ls/IdeaProjects/Todo/src/Test.dex");
    dexObject.parse();
  }

}


