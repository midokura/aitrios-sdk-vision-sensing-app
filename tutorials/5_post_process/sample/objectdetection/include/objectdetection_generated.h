/****************************************************************************
 * Copyright 2022 Sony Semiconductor Solutions Corp. All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 ****************************************************************************/


// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_OBJECTDETECTION_SMARTCAMERA_H_
#define FLATBUFFERS_GENERATED_OBJECTDETECTION_SMARTCAMERA_H_

#include "flatbuffers/flatbuffers.h"

namespace SmartCamera {

struct BoundingBox2d;

struct GeneralObject;

struct ObjectDetectionData;

struct ObjectDetectionTop;

enum BoundingBox {
  BoundingBox_NONE = 0,
  BoundingBox_BoundingBox2d = 1,
  BoundingBox_MIN = BoundingBox_NONE,
  BoundingBox_MAX = BoundingBox_BoundingBox2d
};

inline const BoundingBox (&EnumValuesBoundingBox())[2] {
  static const BoundingBox values[] = {
    BoundingBox_NONE,
    BoundingBox_BoundingBox2d
  };
  return values;
}

inline const char * const *EnumNamesBoundingBox() {
  static const char * const names[] = {
    "NONE",
    "BoundingBox2d",
    nullptr
  };
  return names;
}

inline const char *EnumNameBoundingBox(BoundingBox e) {
  if (e < BoundingBox_NONE || e > BoundingBox_BoundingBox2d) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesBoundingBox()[index];
}

template<typename T> struct BoundingBoxTraits {
  static const BoundingBox enum_value = BoundingBox_NONE;
};

template<> struct BoundingBoxTraits<BoundingBox2d> {
  static const BoundingBox enum_value = BoundingBox_BoundingBox2d;
};

bool VerifyBoundingBox(flatbuffers::Verifier &verifier, const void *obj, BoundingBox type);
bool VerifyBoundingBoxVector(flatbuffers::Verifier &verifier, const flatbuffers::Vector<flatbuffers::Offset<void>> *values, const flatbuffers::Vector<uint8_t> *types);

struct BoundingBox2d FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_LEFT = 4,
    VT_TOP = 6,
    VT_RIGHT = 8,
    VT_BOTTOM = 10
  };
  int32_t left() const {
    return GetField<int32_t>(VT_LEFT, 0);
  }
  int32_t top() const {
    return GetField<int32_t>(VT_TOP, 0);
  }
  int32_t right() const {
    return GetField<int32_t>(VT_RIGHT, 0);
  }
  int32_t bottom() const {
    return GetField<int32_t>(VT_BOTTOM, 0);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<int32_t>(verifier, VT_LEFT) &&
           VerifyField<int32_t>(verifier, VT_TOP) &&
           VerifyField<int32_t>(verifier, VT_RIGHT) &&
           VerifyField<int32_t>(verifier, VT_BOTTOM) &&
           verifier.EndTable();
  }
};

struct BoundingBox2dBuilder {
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_left(int32_t left) {
    fbb_.AddElement<int32_t>(BoundingBox2d::VT_LEFT, left, 0);
  }
  void add_top(int32_t top) {
    fbb_.AddElement<int32_t>(BoundingBox2d::VT_TOP, top, 0);
  }
  void add_right(int32_t right) {
    fbb_.AddElement<int32_t>(BoundingBox2d::VT_RIGHT, right, 0);
  }
  void add_bottom(int32_t bottom) {
    fbb_.AddElement<int32_t>(BoundingBox2d::VT_BOTTOM, bottom, 0);
  }
  explicit BoundingBox2dBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  BoundingBox2dBuilder &operator=(const BoundingBox2dBuilder &);
  flatbuffers::Offset<BoundingBox2d> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<BoundingBox2d>(end);
    return o;
  }
};

inline flatbuffers::Offset<BoundingBox2d> CreateBoundingBox2d(
    flatbuffers::FlatBufferBuilder &_fbb,
    int32_t left = 0,
    int32_t top = 0,
    int32_t right = 0,
    int32_t bottom = 0) {
  BoundingBox2dBuilder builder_(_fbb);
  builder_.add_bottom(bottom);
  builder_.add_right(right);
  builder_.add_top(top);
  builder_.add_left(left);
  return builder_.Finish();
}

struct GeneralObject FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_CLASS_ID = 4,
    VT_BOUNDING_BOX_TYPE = 6,
    VT_BOUNDING_BOX = 8,
    VT_SCORE = 10
  };
  uint32_t class_id() const {
    return GetField<uint32_t>(VT_CLASS_ID, 0);
  }
  BoundingBox bounding_box_type() const {
    return static_cast<BoundingBox>(GetField<uint8_t>(VT_BOUNDING_BOX_TYPE, 0));
  }
  const void *bounding_box() const {
    return GetPointer<const void *>(VT_BOUNDING_BOX);
  }
  template<typename T> const T *bounding_box_as() const;
  const BoundingBox2d *bounding_box_as_BoundingBox2d() const {
    return bounding_box_type() == BoundingBox_BoundingBox2d ? static_cast<const BoundingBox2d *>(bounding_box()) : nullptr;
  }
  float score() const {
    return GetField<float>(VT_SCORE, 0.0f);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint32_t>(verifier, VT_CLASS_ID) &&
           VerifyField<uint8_t>(verifier, VT_BOUNDING_BOX_TYPE) &&
           VerifyOffset(verifier, VT_BOUNDING_BOX) &&
           VerifyBoundingBox(verifier, bounding_box(), bounding_box_type()) &&
           VerifyField<float>(verifier, VT_SCORE) &&
           verifier.EndTable();
  }
};

template<> inline const BoundingBox2d *GeneralObject::bounding_box_as<BoundingBox2d>() const {
  return bounding_box_as_BoundingBox2d();
}

struct GeneralObjectBuilder {
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_class_id(uint32_t class_id) {
    fbb_.AddElement<uint32_t>(GeneralObject::VT_CLASS_ID, class_id, 0);
  }
  void add_bounding_box_type(BoundingBox bounding_box_type) {
    fbb_.AddElement<uint8_t>(GeneralObject::VT_BOUNDING_BOX_TYPE, static_cast<uint8_t>(bounding_box_type), 0);
  }
  void add_bounding_box(flatbuffers::Offset<void> bounding_box) {
    fbb_.AddOffset(GeneralObject::VT_BOUNDING_BOX, bounding_box);
  }
  void add_score(float score) {
    fbb_.AddElement<float>(GeneralObject::VT_SCORE, score, 0.0f);
  }
  explicit GeneralObjectBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  GeneralObjectBuilder &operator=(const GeneralObjectBuilder &);
  flatbuffers::Offset<GeneralObject> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<GeneralObject>(end);
    return o;
  }
};

inline flatbuffers::Offset<GeneralObject> CreateGeneralObject(
    flatbuffers::FlatBufferBuilder &_fbb,
    uint32_t class_id = 0,
    BoundingBox bounding_box_type = BoundingBox_NONE,
    flatbuffers::Offset<void> bounding_box = 0,
    float score = 0.0f) {
  GeneralObjectBuilder builder_(_fbb);
  builder_.add_score(score);
  builder_.add_bounding_box(bounding_box);
  builder_.add_class_id(class_id);
  builder_.add_bounding_box_type(bounding_box_type);
  return builder_.Finish();
}

struct ObjectDetectionData FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_OBJECT_DETECTION_LIST = 4
  };
  const flatbuffers::Vector<flatbuffers::Offset<GeneralObject>> *object_detection_list() const {
    return GetPointer<const flatbuffers::Vector<flatbuffers::Offset<GeneralObject>> *>(VT_OBJECT_DETECTION_LIST);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_OBJECT_DETECTION_LIST) &&
           verifier.VerifyVector(object_detection_list()) &&
           verifier.VerifyVectorOfTables(object_detection_list()) &&
           verifier.EndTable();
  }
};

struct ObjectDetectionDataBuilder {
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_object_detection_list(flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<GeneralObject>>> object_detection_list) {
    fbb_.AddOffset(ObjectDetectionData::VT_OBJECT_DETECTION_LIST, object_detection_list);
  }
  explicit ObjectDetectionDataBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ObjectDetectionDataBuilder &operator=(const ObjectDetectionDataBuilder &);
  flatbuffers::Offset<ObjectDetectionData> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<ObjectDetectionData>(end);
    return o;
  }
};

inline flatbuffers::Offset<ObjectDetectionData> CreateObjectDetectionData(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<GeneralObject>>> object_detection_list = 0) {
  ObjectDetectionDataBuilder builder_(_fbb);
  builder_.add_object_detection_list(object_detection_list);
  return builder_.Finish();
}

inline flatbuffers::Offset<ObjectDetectionData> CreateObjectDetectionDataDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<flatbuffers::Offset<GeneralObject>> *object_detection_list = nullptr) {
  auto object_detection_list__ = object_detection_list ? _fbb.CreateVector<flatbuffers::Offset<GeneralObject>>(*object_detection_list) : 0;
  return SmartCamera::CreateObjectDetectionData(
      _fbb,
      object_detection_list__);
}

struct ObjectDetectionTop FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_PERCEPTION = 4
  };
  const ObjectDetectionData *perception() const {
    return GetPointer<const ObjectDetectionData *>(VT_PERCEPTION);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_PERCEPTION) &&
           verifier.VerifyTable(perception()) &&
           verifier.EndTable();
  }
};

struct ObjectDetectionTopBuilder {
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_perception(flatbuffers::Offset<ObjectDetectionData> perception) {
    fbb_.AddOffset(ObjectDetectionTop::VT_PERCEPTION, perception);
  }
  explicit ObjectDetectionTopBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ObjectDetectionTopBuilder &operator=(const ObjectDetectionTopBuilder &);
  flatbuffers::Offset<ObjectDetectionTop> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<ObjectDetectionTop>(end);
    return o;
  }
};

inline flatbuffers::Offset<ObjectDetectionTop> CreateObjectDetectionTop(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<ObjectDetectionData> perception = 0) {
  ObjectDetectionTopBuilder builder_(_fbb);
  builder_.add_perception(perception);
  return builder_.Finish();
}

inline bool VerifyBoundingBox(flatbuffers::Verifier &verifier, const void *obj, BoundingBox type) {
  switch (type) {
    case BoundingBox_NONE: {
      return true;
    }
    case BoundingBox_BoundingBox2d: {
      auto ptr = reinterpret_cast<const BoundingBox2d *>(obj);
      return verifier.VerifyTable(ptr);
    }
    default: return false;
  }
}

inline bool VerifyBoundingBoxVector(flatbuffers::Verifier &verifier, const flatbuffers::Vector<flatbuffers::Offset<void>> *values, const flatbuffers::Vector<uint8_t> *types) {
  if (!values || !types) return !values && !types;
  if (values->size() != types->size()) return false;
  for (flatbuffers::uoffset_t i = 0; i < values->size(); ++i) {
    if (!VerifyBoundingBox(
        verifier,  values->Get(i), types->GetEnum<BoundingBox>(i))) {
      return false;
    }
  }
  return true;
}

inline const SmartCamera::ObjectDetectionTop *GetObjectDetectionTop(const void *buf) {
  return flatbuffers::GetRoot<SmartCamera::ObjectDetectionTop>(buf);
}

inline const SmartCamera::ObjectDetectionTop *GetSizePrefixedObjectDetectionTop(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<SmartCamera::ObjectDetectionTop>(buf);
}

inline bool VerifyObjectDetectionTopBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<SmartCamera::ObjectDetectionTop>(nullptr);
}

inline bool VerifySizePrefixedObjectDetectionTopBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<SmartCamera::ObjectDetectionTop>(nullptr);
}

inline void FinishObjectDetectionTopBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<SmartCamera::ObjectDetectionTop> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedObjectDetectionTopBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<SmartCamera::ObjectDetectionTop> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace SmartCamera

#endif  // FLATBUFFERS_GENERATED_OBJECTDETECTION_SMARTCAMERA_H_
