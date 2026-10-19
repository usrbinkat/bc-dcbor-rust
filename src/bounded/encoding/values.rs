use super::*;

macro_rules! numbers {
    ($($ty:ty => $convert:expr),* $(,)?) => {$(
        impl Schema for $ty {
            fn instruction(&self, index: usize) -> Instruction<'_> {
                if index != 0 { return Instruction::End; }
                let numeric: Numeric = ($convert)(*self);
                let (major, arg) = numeric.head();
                Instruction::Head(major, arg)
            }
        }
    )*};
}
numbers!(
    u8 => |v| integer(v as i128), u16 => |v| integer(v as i128),
    u32 => |v| integer(v as i128), u64 => |v| integer(v as i128),
    usize => |v| integer(v as i128), i8 => |v| integer(v as i128),
    i16 => |v| integer(v as i128), i32 => |v| integer(v as i128),
    i64 => |v| integer(v as i128),
    f16 => |v| convert_f16(v).prepared(),
    f32 => |v| convert_f32(v).prepared(),
    f64 => |v| convert_f64(v).prepared(),
);
impl Schema for bool {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        if index == 0 {
            Instruction::Head(
                MajorType::Simple,
                Argument::Shortest(if *self { 21 } else { 20 }),
            )
        } else {
            Instruction::End
        }
    }
}
impl Schema for str {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        if index == 0 {
            Instruction::Text(self)
        } else {
            Instruction::End
        }
    }
}
impl Schema for String {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        self.as_str().instruction(index)
    }
}
impl Schema for ByteString {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::Head(
                MajorType::ByteString,
                Argument::Shortest(self.data().len() as u64),
            ),
            1 => Instruction::Bytes(self.data()),
            _ => Instruction::End,
        }
    }
}
impl<T: Schema> Schema for [T] {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        if index == 0 {
            return Instruction::Head(MajorType::Array, Argument::Shortest(self.len() as u64));
        }
        self.get(index - 1)
            .map_or(Instruction::End, |v| Instruction::Child(v))
    }
}
impl<T: Schema> Schema for Vec<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        self.as_slice().instruction(index)
    }
}
impl<T: Schema, const N: usize> Schema for [T; N] {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        self.as_slice().instruction(index)
    }
}
impl<T: Schema> Schema for Option<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        if index != 0 {
            return Instruction::End;
        }
        self.as_ref().map_or(
            Instruction::Head(MajorType::Simple, Argument::Shortest(NULL)),
            |v| Instruction::Child(v),
        )
    }
}
impl<T: Schema + ?Sized> Schema for &T {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        (**self).instruction(index)
    }
}

impl<T: Schema + ?Sized> Schema for Box<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        (**self).instruction(index)
    }
}
impl<T: Schema + ?Sized> Schema for Arc<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        (**self).instruction(index)
    }
}
#[cfg(feature = "std")]
impl<T: Schema + ?Sized> Schema for std::rc::Rc<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        (**self).instruction(index)
    }
}
impl<T: Schema> Schema for Tagged<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::Head(MajorType::Tagged, Argument::Shortest(self.tag)),
            1 => Instruction::Child(&self.value),
            _ => Instruction::End,
        }
    }
}
