// Protocol Buffers - Google's data interchange format
// Copyright 2008 Google Inc.  All rights reserved.
// http://code.google.com/p/protobuf/
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Author: kenton@google.com (Kenton Varda)
//  Based on original Protocol Buffers design by
//  Sanjay Ghemawat, Jeff Dean, and others.

// Copyright (c) 2008-2013, Dave Benson.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Modified to implement C code by Dave Benson.

#ifndef GOOGLE_PROTOBUF_COMPILER_C_FIELD_H__
#define GOOGLE_PROTOBUF_COMPILER_C_FIELD_H__

#include <string>
#include <map>
#include <google/protobuf/stubs/common.h>
#include <google/protobuf/descriptor.h>


namespace google {
namespace protobuf {
  namespace io {
    class Printer;             // printer.h
  }
}

struct riftfopts {
  int enforce;
  int ismsg;
  int agg;
  int flatinline;
  uint32_t inline_max;
  uint32_t string_max;
  uint32_t rw_flags;
  std::string c_type;
  std::string merge_behave;

  riftfopts()
  : enforce(0),
    ismsg(0),
    agg(0),
    flatinline(0),
    inline_max(0),
    string_max(0),
    rw_flags(0)
  {}
};

namespace protobuf {
namespace compiler {
namespace c {

class FieldGenerator {
 public:

  explicit FieldGenerator(const FieldDescriptor *descriptor) : descriptor_(descriptor)  {
    rift_parseopts(descriptor_);
  }
  virtual ~FieldGenerator();

  // Generate definitions to be included in the structure.
  virtual void GenerateStructMembers(io::Printer* printer) const = 0;

  // Generate a static initializer for this field.
  virtual void GenerateDescriptorInitializer(io::Printer* printer) const = 0;

  virtual void GenerateDefaultValueDeclarations(io::Printer* printer) const { }
  virtual void GenerateDefaultValueImplementations(io::Printer* printer) const { }
  virtual string GetDefaultValue() const = 0;

  virtual bool isCType(void) const;

  // Generate members to initialize this field from a static initializer
  virtual void GenerateStaticInit(io::Printer* printer) const = 0;

  virtual void AssignStructMembers(io::Printer* printer, int num) const = 0;

  virtual string GetTypeName() const = 0;
  virtual string GetPointerType() const = 0;

  // Generate MetaData Macro for this field.
  void GenerateMetaDataMacro(io::Printer* printer, unsigned index) const;

  struct riftfopts riftopts;

  void rift_parseopts(const FieldDescriptor *descriptor_);

  // Gi code generation support functions.
  virtual string GetGiTypeName(bool use_const = true) const = 0;
  string GetParentGiCIdentifier(const char *operation, const string& field) const;
  string GetParentGiCIdentifier(const char *operation) const;
  string GetGiCIdentifier(const char *operation) const;

  // pure virtual functions.
  virtual string GetGiReturnAnnotations() const = 0;
  virtual string GetGiGetterReturnType() const = 0;
  virtual string GetGiGetterParameterList() const = 0;
  virtual string GetGiSetterAnnotations() const = 0;
  virtual string GetGiSetterParameterList() const = 0;
  virtual void GenerateGiCGetterMethod(io::Printer* printer) const = 0;
  virtual void GenerateGiCSetterMethod(io::Printer* printer) const = 0;

  string GetGiBoxedFieldName() const;
  string GetQuantifierField() const;
  bool HasQuantifierField() const;
  void GenerateGiHSupportMethodDecls(io::Printer* printer) const;
  void GenerateGiCSupportMethodDefs(io::Printer* printer) const;
  virtual void GenerateGiCreateMethod(io::Printer* printer) const { };
  virtual string GetGiCreateParameterList() const { };
  virtual bool HasLengthOut() const;

 protected:
  void GenerateDescriptorInitializerGeneric(io::Printer* printer,
                                            bool optional_uses_has,
                                            const string &type_macro,
                                            const string &descriptor_addr) const;
  const FieldDescriptor *descriptor_;

 private:

  GOOGLE_DISALLOW_EVIL_CONSTRUCTORS(FieldGenerator);
};

// Convenience class which constructs FieldGenerators for a Descriptor.
class FieldGeneratorMap {
 public:
  explicit FieldGeneratorMap(const Descriptor* descriptor);
  ~FieldGeneratorMap();

  const FieldGenerator& get(const FieldDescriptor* field) const;

 private:
  const Descriptor* descriptor_;
  scoped_array<scoped_ptr<FieldGenerator> > field_generators_;

  static FieldGenerator* MakeGenerator(const FieldDescriptor* field);

  GOOGLE_DISALLOW_EVIL_CONSTRUCTORS(FieldGeneratorMap);
};

}  // namespace c
}  // namespace compiler
}  // namespace protobuf

}  // namespace google
#endif  // GOOGLE_PROTOBUF_COMPILER_C_FIELD_H__
