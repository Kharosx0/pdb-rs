//! Decodes items in a `LF_FIELDLIST` complex list.

use super::*;
use tracing::error;

/// Represents the data stored within an `LF_FIELDLIST` type string. This can be decoded using
/// the `iter()` method.
#[derive(Clone)]
pub struct FieldList<'a> {
    #[allow(missing_docs)]
    pub bytes: &'a [u8],
}

impl<'a> FieldList<'a> {
    /// Iterates the fields within an `LF_FIELDLIST` type string.
    ///
    /// Iteration is *fail-closed*: if a field record cannot be decoded (for example, an
    /// unrecognized `LF_*` item kind), the iterator yields `Err` and then ends, rather
    /// than silently truncating the field list. Silently stopping would make a caller
    /// that computes record layout produce a wrong answer with no indication of error.
    pub fn iter(&self) -> IterFields<'a> {
        IterFields { bytes: self.bytes }
    }
}

impl<'a> Debug for FieldList<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if f.alternate() {
            let mut list = f.debug_list();
            for f in self.iter() {
                match f {
                    Ok(f) => {
                        list.entry(&f);
                    }
                    Err(e) => {
                        list.entry(&format_args!("<error: {e}>"));
                    }
                }
            }
            list.finish()
        } else {
            f.write_str("FieldList")
        }
    }
}

/// Iterates the fields within an `LF_FIELDLIST` type string.
pub struct IterFields<'a> {
    #[allow(missing_docs)]
    pub bytes: &'a [u8],
}

/// Represents one field within an `LF_FIELDLIST` type string.
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub enum Field<'a> {
    BaseClass(BaseClass<'a>),
    DirectVirtualBaseClass(DirectVirtualBaseClass<'a>),
    IndirectVirtualBaseClass(IndirectVirtualBaseClass<'a>),
    Enumerate(Enumerate<'a>),
    FriendFn(FriendFn<'a>),
    Index(TypeIndex),
    Member(Member<'a>),
    StaticMember(StaticMember<'a>),
    Method(Method<'a>),
    NestedType(NestedType<'a>),
    VFuncTable(TypeIndex),
    FriendClass(TypeIndex),
    OneMethod(OneMethod<'a>),
    VFuncOffset(VFuncOffset),
    NestedTypeEx(NestedTypeEx<'a>),
}

#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub struct NestedType<'a> {
    pub nested_ty: TypeIndex,
    pub name: &'a BStr,
}

impl<'a> Parse<'a> for NestedType<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        p.skip(2)?; // padding
        Ok(Self {
            nested_ty: p.type_index()?,
            name: p.strz()?,
        })
    }
}

#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub struct BaseClass<'a> {
    pub attr: u16,
    pub ty: TypeIndex,
    pub offset: Number<'a>,
}

impl<'a> Parse<'a> for BaseClass<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        let attr = p.u16()?;
        let ty = p.type_index()?;
        let offset = p.number()?;
        Ok(BaseClass { attr, ty, offset })
    }
}

/// This is used by both DirectVirtualBaseClass and IndirectVirtualBaseClass.
#[allow(missing_docs)]
#[repr(C)]
#[derive(Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct VirtualBaseClassFixed {
    pub attr: U16<LE>,
    pub btype: TypeIndexLe,
    pub vbtype: TypeIndexLe,
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct DirectVirtualBaseClass<'a> {
    pub fixed: &'a VirtualBaseClassFixed,
    pub vbpoff: Number<'a>,
    pub vboff: Number<'a>,
}

impl<'a> Parse<'a> for DirectVirtualBaseClass<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        Ok(Self {
            fixed: p.get()?,
            vbpoff: p.number()?,
            vboff: p.number()?,
        })
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct IndirectVirtualBaseClass<'a> {
    pub fixed: &'a VirtualBaseClassFixed,
    pub vbpoff: Number<'a>,
    pub vboff: Number<'a>,
}

impl<'a> Parse<'a> for IndirectVirtualBaseClass<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        let fixed = p.get()?;
        let vbpoff = p.number()?;
        let vboff = p.number()?;
        Ok(Self {
            fixed,
            vbpoff,
            vboff,
        })
    }
}

#[allow(missing_docs)]
#[derive(Clone)]
pub struct Enumerate<'a> {
    pub attr: u16,
    pub value: Number<'a>,
    pub name: &'a BStr,
}

impl<'a> Parse<'a> for Enumerate<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        Ok(Self {
            attr: p.u16()?,
            value: p.number()?,
            name: p.strz()?,
        })
    }
}

impl<'a> Debug for Enumerate<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} = {}", self.name, self.value)
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct FriendFn<'a> {
    pub ty: TypeIndex,
    pub name: &'a BStr,
}

impl<'a> Parse<'a> for FriendFn<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        p.skip(2)?; // padding
        Ok(Self {
            ty: p.type_index()?,
            name: p.strz()?,
        })
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct OneMethod<'a> {
    pub attr: u16,
    pub ty: TypeIndex,
    pub vbaseoff: u32,
    pub name: &'a BStr,
}

impl<'a> Parse<'a> for OneMethod<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        let attr = p.u16()?;
        let ty = p.type_index()?;
        let vbaseoff = if introduces_virtual(attr) {
            p.u32()?
        } else {
            0
        };
        let name = p.strz()?;
        Ok(OneMethod {
            attr,
            ty,
            vbaseoff,
            name,
        })
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct VFuncOffset {
    pub vtable_ty: TypeIndex,
    pub offset: u32,
}

impl<'a> Parse<'a> for VFuncOffset {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        p.skip(2)?; // padding
        let vtable_ty = p.type_index()?;
        let offset = p.u32()?;
        Ok(Self { vtable_ty, offset })
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct NestedTypeEx<'a> {
    pub attr: u16,
    pub ty: TypeIndex,
    pub name: &'a BStr,
}

impl<'a> Parse<'a> for NestedTypeEx<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        let attr = p.u16()?;
        let ty = p.type_index()?;
        let name = p.strz()?;
        Ok(Self { attr, ty, name })
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct Member<'a> {
    pub attr: u16,
    pub ty: TypeIndex,
    pub offset: Number<'a>,
    pub name: &'a BStr,
}

impl<'a> Parse<'a> for Member<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        Ok(Self {
            attr: p.u16()?,
            ty: p.type_index()?,
            offset: p.number()?,
            name: p.strz()?,
        })
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct StaticMember<'a> {
    pub attr: u16,
    pub ty: TypeIndex,
    pub name: &'a BStr,
}

impl<'a> Parse<'a> for StaticMember<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        Ok(Self {
            attr: p.u16()?,
            ty: p.type_index()?,
            name: p.strz()?,
        })
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct Method<'a> {
    pub count: u16,
    pub methods: TypeIndex,
    pub name: &'a BStr,
}

impl<'a> Parse<'a> for Method<'a> {
    fn from_parser(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        Ok(Self {
            count: p.u16()?,
            methods: p.type_index()?,
            name: p.strz()?,
        })
    }
}

impl<'a> Iterator for IterFields<'a> {
    type Item = Result<Field<'a>, ParserError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let mut p = Parser::new(self.bytes);

        let rest = p.peek_rest();

        // Check for padding (alignment) bytes.
        let mut padding_len = 0;
        while padding_len < rest.len() && rest[padding_len] >= 0xf0 {
            padding_len += 1;
        }
        if padding_len > 0 {
            let _ = p.skip(padding_len);
        }

        if p.is_empty() {
            return None;
        }

        match Field::parse(&mut p) {
            Ok(f) => {
                self.bytes = p.into_rest();
                Some(Ok(f))
            }
            Err(e) => {
                // Fuse the iterator: the remaining bytes cannot be located without
                // knowing the length of the item we failed to decode.
                self.bytes = &[];
                Some(Err(e))
            }
        }
    }
}

impl<'a> Field<'a> {
    /// Parses one field within an `LF_FIELDLIST` type string.
    ///
    /// Unlike most of the `parse()` methods defined in this library, this function requires a
    /// `Parser` instance, rather than just working directly with `&[u8]`. This is because the
    /// field records do not have a length field; the type of the field is required to know how
    /// many bytes to decode in each field.
    ///
    /// So the act of parsing a field is what is needed for locating the next field.
    pub fn parse(p: &mut Parser<'a>) -> Result<Self, ParserError> {
        let item_kind = Leaf(p.u16()?);

        Ok(match item_kind {
            Leaf::LF_BCLASS => Self::BaseClass(p.parse()?),
            Leaf::LF_VBCLASS => Self::DirectVirtualBaseClass(p.parse()?),
            Leaf::LF_IVBCLASS => Self::IndirectVirtualBaseClass(p.parse()?),
            Leaf::LF_ENUMERATE => Self::Enumerate(p.parse()?),
            Leaf::LF_FRIENDFCN => Self::FriendFn(p.parse()?),

            Leaf::LF_INDEX => {
                p.skip(2)?; // padding
                let ty = p.type_index()?;
                Self::Index(ty)
            }

            Leaf::LF_MEMBER => Self::Member(p.parse()?),
            Leaf::LF_STMEMBER => Self::StaticMember(p.parse()?),
            Leaf::LF_METHOD => Self::Method(p.parse()?),
            Leaf::LF_NESTEDTYPE => Self::NestedType(p.parse()?),

            Leaf::LF_VFUNCTAB => {
                p.skip(2)?; // padding
                let vtable_ty = p.type_index()?;
                Self::VFuncTable(vtable_ty)
            }

            Leaf::LF_FRIENDCLS => {
                p.skip(2)?; // padding
                let ty = p.type_index()?; // friend class type
                Self::FriendClass(ty)
            }

            Leaf::LF_ONEMETHOD => Self::OneMethod(p.parse()?),
            Leaf::LF_VFUNCOFF => Self::VFuncOffset(p.parse()?),
            Leaf::LF_NESTEDTYPEEX => Self::NestedTypeEx(p.parse()?),

            unknown_item_kind => {
                error!(?unknown_item_kind, "unrecognized item within LF_FIELDLIST",);
                return Err(ParserError::new());
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `LF_MEMBER` item: attr(u16), ty(u32), offset(numeric), name(strz).
    fn member_item(name: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&Leaf::LF_MEMBER.0.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // attr
        v.extend_from_slice(&0x1000u32.to_le_bytes()); // ty
        v.extend_from_slice(&0u16.to_le_bytes()); // offset: immediate numeric 0
        v.extend_from_slice(name);
        v.push(0);
        v
    }

    /// A well-formed field list decodes every item and then ends cleanly.
    #[test]
    fn iter_fields_decodes_all_items() {
        let mut bytes = member_item(b"a");
        bytes.extend_from_slice(&member_item(b"b"));
        let list = FieldList { bytes: &bytes };
        let got: Vec<_> = list.iter().collect();
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|f| f.is_ok()));
    }

    /// An unrecognized item kind must surface an error, NOT silently end iteration.
    ///
    /// Silently truncating a field list makes a caller that computes record layout
    /// produce a wrong answer with no indication that anything went wrong.
    #[test]
    fn iter_fields_reports_unrecognized_item_instead_of_truncating() {
        let mut bytes = member_item(b"a");
        bytes.extend_from_slice(&0xdeadu16.to_le_bytes()); // not a valid LF_* item kind
        let list = FieldList { bytes: &bytes };
        let got: Vec<_> = list.iter().collect();
        assert_eq!(got.len(), 2, "expected the good field and then an error");
        assert!(got[0].is_ok());
        assert!(got[1].is_err(), "unrecognized item kind must yield Err");
        // The iterator is fused after the error.
        assert!(list.iter().nth(2).is_none());
    }
}
