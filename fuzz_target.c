#define PY_SSIZE_T_CLEAN
#include <Python.h>

#pragma clang optimize off

static PyObject *corruption(PyObject* self, PyObject* args) {
    char arr[3];
    Py_buffer name;

    if (!PyArg_ParseTuple(args, "y*", &name))
        return NULL;

    if (name.buf != NULL) {
        if (strcmp(name.buf, "FUZZ") == 0) {
            arr[0] = 'B';
            arr[1] = 'O';
            arr[2] = 'O';
            arr[3] = 'M';
        }
    }

    PyBuffer_Release(&name);
    Py_RETURN_NONE;
}

static PyMethodDef MemoryMethods[] = {
    {"corruption", corruption, METH_VARARGS, "BOOM!"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef memory_module = {
    PyModuleDef_HEAD_INIT,
    "memory",
    "BOOM!",
    -1,
    MemoryMethods
};

PyMODINIT_FUNC PyInit_memory(void) {
    return PyModule_Create(&memory_module);
}
