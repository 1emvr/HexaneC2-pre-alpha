use std::ptr::NonNull;

pub struct LinkedList<T> {
    pub(crate) head: Option<T>,
    pub(crate) next: Option<NonNull<LinkedList<T>>>,
}

impl<T> LinkedList<T> {
    pub fn new() -> Self {
        LinkedList {
            head: None,
            next: None,
        }
    }

    pub fn push(&mut self, value: T) {
        if self.head.is_none() {
            self.head = Some(value)

        } else {
            let new_head = Box::new(LinkedList::<T> {
                head: Some(value),
                next: None,
            });

            if self.next.is_none() {
                let pointer: NonNull<LinkedList<T>> = Box::leak(new_head).into();
                self.next = Some(pointer);
            } else {
                let mut pointer: NonNull<LinkedList<T>> = Box::leak(new_head).into();
                unsafe {
                    pointer.as_mut().next = self.next;
                }
                self.next = Some(pointer);
            }
        }
    }

    pub fn peek(&mut self) -> Option<&mut T> {
        if let Some(mut next) = self.next {
            unsafe{ next.as_mut().head.as_mut() }
        } else {
            None
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.next.is_none() {
            None

        } else {
            let mut next = self.next.unwrap();
            let only_one: bool = unsafe { next.as_mut().next.is_none() };

            if only_one == true {
                let next_box = unsafe { Box::from_raw(next.as_ptr()) };

                self.next = None;
                next_box.head
            } else {
                let next_next = unsafe { next.as_mut().next };
                let next_box = unsafe { Box::from_raw(next.as_ptr()) };

                self.next = next_next;
                next_box.head
            }
        }
    }
}

