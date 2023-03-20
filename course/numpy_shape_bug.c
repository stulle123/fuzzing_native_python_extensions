NPY_NO_EXPORT PyObject *
PyArray_Resize(PyArrayObject *self, PyArray_Dims *newshape, int refcheck,
        NPY_ORDER order)
{
    // npy_intp is `long long`
    npy_intp* new_dimensions = newshape->ptr;
    npy_intp newsize = 1;
    int new_nd = newshape->len;
    int k;
    // NPY_MAX_INTP is MAX_LONGLONG (0x7fffffffffffffff)
    npy_intp largest = NPY_MAX_INTP / PyArray_DESCR(self)->elsize;
    for(k = 0; k < new_nd; k++) {
        newsize *= new_dimensions[k];
        if (newsize <= 0 || newsize > largest) {
            return PyErr_NoMemory();
        }
    }
    if (newsize == 0) {
        sd = PyArray_DESCR(self)->elsize;
    }
    else {
        sd = newsize*PyArray_DESCR(self)->elsize;
    }
    /* Reallocate space if needed */
    new_data = realloc(PyArray_DATA(self), sd);
    if (new_data == NULL) {
        PyErr_SetString(PyExc_MemoryError,
                “cannot allocate memory for array”);
        return NULL;
    }
    ((PyArrayObject_fields *)self)->data = new_data;
