use std::sync::Mutex;

pub struct ResourceAllocator {
    inner: Mutex<ResourceAllocatorInner>,
}

struct ResourceAllocatorInner {
    fwmarks: Vec<bool>,
    route_tables: Vec<bool>,
}

impl ResourceAllocator {
    pub fn new(max_fwmarks: u32, max_route_tables: u32) -> Self {
        Self {
            inner: Mutex::new(ResourceAllocatorInner {
                fwmarks: vec![false; max_fwmarks as usize],
                route_tables: vec![false; max_route_tables as usize],
            }),
        }
    }

    pub fn allocate_fwmark(&self) -> Option<u32> {
        let mut inner = self.inner.lock().unwrap();
        for (i, used) in inner.fwmarks.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Some(i as u32 + 100); // Start from 100
            }
        }
        None
    }

    pub fn release_fwmark(&self, mark: u32) {
        let mut inner = self.inner.lock().unwrap();
        let index = (mark - 100) as usize;
        if index < inner.fwmarks.len() {
            inner.fwmarks[index] = false;
        }
    }

    pub fn allocate_route_table(&self) -> Option<u32> {
        let mut inner = self.inner.lock().unwrap();
        for (i, used) in inner.route_tables.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Some(i as u32 + 100); // Start from 100
            }
        }
        None
    }

    pub fn release_route_table(&self, table: u32) {
        let mut inner = self.inner.lock().unwrap();
        let index = (table - 100) as usize;
        if index < inner.route_tables.len() {
            inner.route_tables[index] = false;
        }
    }

    pub fn allocated_fwmarks(&self) -> Vec<u32> {
        let inner = self.inner.lock().unwrap();
        inner
            .fwmarks
            .iter()
            .enumerate()
            .filter(|(_, used)| **used)
            .map(|(i, _)| i as u32 + 100)
            .collect()
    }

    pub fn allocated_route_tables(&self) -> Vec<u32> {
        let inner = self.inner.lock().unwrap();
        inner
            .route_tables
            .iter()
            .enumerate()
            .filter(|(_, used)| **used)
            .map(|(i, _)| i as u32 + 100)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fwmark_allocation() {
        let allocator = ResourceAllocator::new(10, 10);

        let mark1 = allocator.allocate_fwmark().unwrap();
        let mark2 = allocator.allocate_fwmark().unwrap();

        assert_eq!(mark1, 100);
        assert_eq!(mark2, 101);

        allocator.release_fwmark(mark1);

        let mark3 = allocator.allocate_fwmark().unwrap();
        assert_eq!(mark3, 100); // Reuse released mark
    }

    #[test]
    fn test_route_table_allocation() {
        let allocator = ResourceAllocator::new(10, 10);

        let table1 = allocator.allocate_route_table().unwrap();
        let table2 = allocator.allocate_route_table().unwrap();

        assert_eq!(table1, 100);
        assert_eq!(table2, 101);
    }

    #[test]
    fn test_exhaustion() {
        let allocator = ResourceAllocator::new(2, 2);

        allocator.allocate_fwmark().unwrap();
        allocator.allocate_fwmark().unwrap();
        assert!(allocator.allocate_fwmark().is_none());
    }
}
