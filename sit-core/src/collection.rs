//! Items collection

use std::error;
use super::Item as ItemTrait;

/// Items collection
pub trait Collection {
    /// Item
    type Item: ItemTrait;
    /// Error
    type Error: error::Error;
    /// Item iterator
    type ItemIter: Iterator<Item = Self::Item>;

    /// Returns an unordered (as in "order not defined") item iterator
    fn item_iter(self) -> Result<Self::ItemIter, Self::Error>;

    /// Creates and returns a new item with a unique ID
    fn new_item(self) -> Result<Self::Item, Self::Error>;

    /// Creates and returns a new item with a specific name. Will fail
    /// if there's an item with the same name.
    fn new_named_item<S: AsRef<str>>(self, name: S) -> Result<Self::Item, Self::Error>;

    /// Finds an item by name (if there is one)
    fn item<S: AsRef<str>>(self, name: S) -> Option<Self::Item>;

}