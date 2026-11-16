// SPDX-License-Identifier: MIT
//
// MIT License
//
// Copyright (c) 2026 RustPython Team
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Windows `_csv`, derived from RustPython `rustpython-stdlib` 0.6.0.
//!
//! Source: `crates/stdlib/src/csv.rs` at upstream commit
//! `b2626c56dedfbd7d6f516e53f2fc392a514a0b31`.
//! Published file SHA-256: `13138e68b7881fb8f454015f2def2325d56477e13a481c298c1a597c7a07174e`.
//! Parsing and formatting retain the upstream implementation. Local changes make
//! the registry and field-size limit module-owned, validate delimiter strings without
//! native recursion, and keep writer callbacks outside locks. Imports use the VM's
//! public embedding API and upstream's `itertools` iterator helpers.
//! Syntax characters are ASCII; field contents may be Unicode.
//! Registered only on Windows; other hosts use the published stdlib module.

pub(crate) use _csv::module_def;

#[::rustpython_vm::pymodule]
mod _csv {
    use itertools::Itertools;
    use parking_lot::Mutex;
    use rustpython_vm::common as rustpython_common;
    use rustpython_vm::common::lock::PyMutex;
    use rustpython_vm::common::wtf8::Wtf8Buf;
    use rustpython_vm::{
        AsObject, Py, PyObject, PyObjectRef, PyPayload, PyRef, PyResult, TryFromObject,
        VirtualMachine,
        builtins::{
            PyBaseExceptionRef, PyInt, PyModule, PyNone, PyStr, PyType, PyTypeRef, PyUtf8StrRef,
        },
        function::{ArgIterable, ArgumentError, FromArgs, FuncArgs, OptionalArg, Param},
        protocol::{PyIter, PyIterReturn, PyNumber},
        types::{Callable, Constructor, IterNext, Iterable, SelfIter},
    };
    use rustpython_vm::{FromArgs, Traverse, match_class, pyclass};
    use std::collections::HashMap;
    use std::fmt;

    #[pyattr]
    const QUOTE_MINIMAL: i32 = QuoteStyle::Minimal as i32;

    #[pyattr]
    const QUOTE_ALL: i32 = QuoteStyle::All as i32;

    #[pyattr]
    const QUOTE_NONNUMERIC: i32 = QuoteStyle::Nonnumeric as i32;

    #[pyattr]
    const QUOTE_NONE: i32 = QuoteStyle::None as i32;

    #[pyattr]
    const QUOTE_STRINGS: i32 = QuoteStyle::Strings as i32;

    #[pyattr]
    const QUOTE_NOTNULL: i32 = QuoteStyle::Notnull as i32;

    #[pyattr(name = "__version__")]
    const __VERSION__: &str = "1.0";

    #[pyattr(name = "Error", once)]
    fn error(vm: &VirtualMachine) -> PyTypeRef {
        vm.ctx.new_exception_type(
            "_csv",
            "Error",
            Some(vec![vm.ctx.exceptions.exception_type.to_owned()]),
        )
    }

    // Windows Lambda accounts allocations by interpreter environment. A process-global
    // registry would let a second interpreter grow capacity owned by the first. Follow
    // the per-module state pattern used by `_elementtree`, so registrations and their
    // storage remain with the interpreter that owns them throughout warm reuse.
    #[pyclass(no_attr, module = "_csv", name = "_csv_state")]
    #[derive(Debug, PyPayload)]
    struct CsvState {
        dialects: Mutex<HashMap<String, PyDialect>>,
        field_limit: Mutex<isize>,
    }

    impl Default for CsvState {
        fn default() -> Self {
            Self {
                dialects: Mutex::new(HashMap::new()),
                field_limit: Mutex::new(131072),
            }
        }
    }

    #[pyclass(flags(DISALLOW_INSTANTIATION))]
    impl CsvState {}

    fn module_state(vm: &VirtualMachine) -> PyResult<PyRef<CsvState>> {
        let modules = vm.sys_module.get_attr("modules", vm)?;
        let module = match modules.get_item("_csv", vm) {
            Ok(module) => module,
            Err(_) => vm.import("_csv", 0)?,
        };
        module
            .get_attr("_state", vm)?
            .downcast::<CsvState>()
            .map_err(|_| vm.new_runtime_error("_csv state is corrupted"))
    }

    pub(crate) fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
        __module_exec(vm, module);
        module.set_attr("_state", CsvState::default().into_ref(&vm.ctx), vm)?;
        Ok(())
    }

    fn with_dialects<R>(
        vm: &VirtualMachine,
        f: impl FnOnce(&mut HashMap<String, PyDialect>) -> R,
    ) -> PyResult<R> {
        let state = module_state(vm)?;
        let result = f(&mut state.dialects.lock());
        Ok(result)
    }

    fn current_field_limit(vm: &VirtualMachine) -> PyResult<isize> {
        let state = module_state(vm)?;
        let limit = *state.field_limit.lock();
        Ok(limit)
    }

    fn set_field_limit(vm: &VirtualMachine, limit: isize) -> PyResult<()> {
        let state = module_state(vm)?;
        *state.field_limit.lock() = limit;
        Ok(())
    }

    fn new_csv_error(vm: &VirtualMachine, msg: impl Into<Wtf8Buf>) -> PyBaseExceptionRef {
        vm.new_exception_msg(super::_csv::error(vm), msg.into())
    }

    fn new_not_utf8_error(
        vm: &VirtualMachine,
        bytes: &[u8],
        err: core::str::Utf8Error,
    ) -> PyBaseExceptionRef {
        vm.new_unicode_decode_error(
            vm.ctx.new_str("utf-8"),
            vm.ctx.new_bytes(bytes.to_vec()),
            err.valid_up_to(),
            err.error_len()
                .map_or(bytes.len(), |n| err.valid_up_to() + n),
            vm.ctx.new_str("csv not utf8"),
        )
    }

    #[pyattr]
    #[pyclass(module = "_csv", name = "Dialect")]
    #[derive(Debug, PyPayload, Clone)]
    struct PyDialect {
        delimiter: u8,
        quotechar: Option<u8>,
        escapechar: Option<u8>,
        doublequote: bool,
        skipinitialspace: bool,
        lineterminator: String,
        quoting: QuoteStyle,
        strict: bool,
    }

    impl Constructor for PyDialect {
        type Args = PyObjectRef;

        fn py_new(_cls: &Py<PyType>, obj: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
            let dialect = Self::try_from_object(vm, obj)?;
            validate_dialect(vm, &dialect)?;
            Ok(dialect)
        }
    }

    #[pyclass(with(Constructor))]
    impl PyDialect {
        #[pygetset]
        fn delimiter(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyStr> {
            vm.ctx.new_str(format!("{}", zelf.delimiter as char))
        }

        #[pygetset]
        fn quotechar(zelf: &Py<Self>, vm: &VirtualMachine) -> Option<PyRef<PyStr>> {
            Some(vm.ctx.new_str(format!("{}", zelf.quotechar? as char)))
        }

        #[pygetset]
        fn doublequote(zelf: &Py<Self>) -> bool {
            zelf.doublequote
        }

        #[pygetset]
        fn skipinitialspace(zelf: &Py<Self>) -> bool {
            zelf.skipinitialspace
        }

        #[pygetset]
        fn lineterminator(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyStr> {
            vm.ctx.new_str(zelf.lineterminator.clone())
        }

        #[pygetset]
        fn quoting(zelf: &Py<Self>) -> isize {
            zelf.quoting.into()
        }

        #[pygetset]
        fn escapechar(zelf: &Py<Self>, vm: &VirtualMachine) -> Option<PyRef<PyStr>> {
            Some(vm.ctx.new_str(format!("{}", zelf.escapechar? as char)))
        }

        #[pygetset(name = "strict")]
        fn get_strict(zelf: &Py<Self>) -> bool {
            zelf.strict
        }
    }

    fn parse_delimiter_from_obj(vm: &VirtualMachine, obj: &PyObject) -> PyResult<u8> {
        match obj.downcast_ref::<PyStr>() {
            Some(value) => parse_single_char(value, vm, |len| {
                vm.new_type_error(format!(
                    r#""delimiter" must be a unicode character, not a string of length {len}"#
                ))
            }),
            None => Err(vm.new_type_error(format!(
                r#""delimiter" must be a unicode character, not {}"#,
                obj.class().name()
            ))),
        }
    }

    fn parse_quotechar_from_obj(vm: &VirtualMachine, obj: &PyObject) -> PyResult<Option<u8>> {
        match_class!(match obj.get_attr("quotechar", vm)? {
            s @ PyStr => {
                Ok(Some(parse_single_char(&s, vm, |len| {
                    new_csv_error(
                        vm,
                        format!(
                            r#""quotechar" must be a unicode character or None, not a string of length {len}"#
                        ),
                    )
                })?))
            }
            _n @ PyNone => {
                Ok(None)
            }
            attr => {
                Err(new_csv_error(
                    vm,
                    format!(
                        r#""quotechar" must be a unicode character or None, not {}"#,
                        attr.class().name()
                    ),
                ))
            }
        })
    }

    fn parse_escapechar_from_obj(vm: &VirtualMachine, obj: &PyObject) -> PyResult<Option<u8>> {
        match_class!(match obj.get_attr("escapechar", vm)? {
            s @ PyStr => {
                Ok(Some(parse_single_char(&s, vm, |len| {
                    new_csv_error(
                        vm,
                        format!(
                            r#""escapechar" must be a unicode character or None, not a string of length {len}"#
                        ),
                    )
                })?))
            }
            _n @ PyNone => {
                Ok(None)
            }
            attr => {
                Err(vm.new_type_error(format!(
                    r#""escapechar" must be a unicode character or None, not {}"#,
                    attr.class().name()
                )))
            }
        })
    }

    fn parse_lineterminator<'a>(vm: &VirtualMachine, s: &'a Py<PyStr>) -> PyResult<&'a str> {
        s.to_str()
            .ok_or_else(|| new_csv_error(vm, r#""lineterminator" must be a string"#))
    }

    fn prase_lineterminator_from_obj(vm: &VirtualMachine, obj: &PyObject) -> PyResult<String> {
        match_class!(match obj.get_attr("lineterminator", vm)? {
            s @ PyStr => {
                // Preserve the complete terminator, which need not be one character.
                let value = parse_lineterminator(vm, &s)?;
                Ok(value.to_owned())
            }
            attr => {
                Err(vm.new_type_error(format!(
                    r#""lineterminator" must be a string, not {}"#,
                    attr.class().name()
                )))
            }
        })
    }

    fn parse_single_char(
        s: &Py<PyStr>,
        vm: &VirtualMachine,
        error: impl Fn(usize) -> PyBaseExceptionRef,
    ) -> PyResult<u8> {
        let ch = s
            .as_wtf8()
            .code_points()
            .exactly_one()
            .map_err(|_| error(s.char_len()))?;
        match u8::try_from(ch.to_u32()) {
            Ok(value) if value.is_ascii() => Ok(value),
            _ => Err(new_csv_error(
                vm,
                "non-ASCII CSV delimiter, quote, or escape characters are unsupported",
            )),
        }
    }

    fn prase_quoting_from_obj(vm: &VirtualMachine, obj: &PyObject) -> PyResult<QuoteStyle> {
        match_class!(match obj.get_attr("quoting", vm)? {
            i @ PyInt => {
                Ok(i.try_to_primitive::<isize>(vm)?
                    .try_into()
                    .map_err(|_| vm.new_type_error(r#"bad "quoting" value"#))?)
            }
            attr => {
                Err(vm.new_type_error(format!(
                    r#""quoting" must be string or None, not {}"#,
                    attr.class().name()
                )))
            }
        })
    }

    impl TryFromObject for PyDialect {
        fn try_from_object(vm: &VirtualMachine, obj: PyObjectRef) -> PyResult<Self> {
            let delimiter_obj = obj.get_attr("delimiter", vm)?;
            let delimiter = parse_delimiter_from_obj(vm, &delimiter_obj)?;
            let quotechar = parse_quotechar_from_obj(vm, &obj)?;
            let escapechar = parse_escapechar_from_obj(vm, &obj)?;
            let doublequote = obj.get_attr("doublequote", vm)?.try_to_bool(vm)?;
            let skipinitialspace = obj.get_attr("skipinitialspace", vm)?.try_to_bool(vm)?;
            let lineterminator = prase_lineterminator_from_obj(vm, &obj)?;
            let quoting = prase_quoting_from_obj(vm, &obj)?;

            let strict = if let Ok(t) = obj.get_attr("strict", vm) {
                t.try_to_bool(vm).unwrap_or(false)
            } else {
                false
            };

            Ok(Self {
                delimiter,
                quotechar,
                escapechar,
                doublequote,
                skipinitialspace,
                lineterminator,
                quoting,
                strict,
            })
        }
    }

    #[derive(FromArgs)]
    struct DialectName {
        #[pyarg(any)]
        name: PyObjectRef,
    }

    #[pyfunction]
    fn register_dialect(
        name: PyObjectRef,
        opts: FormatOptions,
        vm: &VirtualMachine,
    ) -> PyResult<()> {
        let name = name
            .downcast::<PyStr>()
            .map_err(|_| vm.new_type_error("argument 0 must be a string"))?;

        let name: PyUtf8StrRef = name.try_into_utf8(vm)?;

        let dialect = opts.result(vm)?;
        validate_dialect(vm, &dialect)?;
        with_dialects(vm, |dialects| {
            dialects.insert(name.as_str().to_owned(), dialect);
        })?;

        Ok(())
    }

    #[pyfunction]
    fn get_dialect(DialectName { name }: DialectName, vm: &VirtualMachine) -> PyResult<PyDialect> {
        let name = name.downcast::<PyStr>().map_err(|obj| {
            new_csv_error(
                vm,
                format!("argument 0 must be a string, not '{}'", obj.class().name()),
            )
        })?;

        let name: PyUtf8StrRef = name.try_into_utf8(vm)?;
        if let Some(dialect) = with_dialects(vm, |dialects| dialects.get(name.as_str()).cloned())? {
            return Ok(dialect);
        }

        Err(new_csv_error(vm, "unknown dialect"))
    }

    #[pyfunction]
    fn unregister_dialect(DialectName { name }: DialectName, vm: &VirtualMachine) -> PyResult<()> {
        let name = name.downcast::<PyStr>().map_err(|obj| {
            new_csv_error(
                vm,
                format!("argument 0 must be a string, not '{}'", obj.class().name()),
            )
        })?;

        let name: PyUtf8StrRef = name.try_into_utf8(vm)?;
        if let Some(_removed) = with_dialects(vm, |dialects| dialects.remove(name.as_str()))? {
            return Ok(());
        }

        Err(new_csv_error(vm, "unknown dialect"))
    }

    #[pyfunction]
    fn list_dialects(vm: &VirtualMachine) -> PyResult<rustpython_vm::builtins::PyListRef> {
        let t = with_dialects(vm, |dialects| {
            dialects
                .keys()
                .cloned()
                .map(|x| vm.ctx.new_str(x).into())
                .collect_vec()
        })?;
        Ok(vm.ctx.new_list(t))
    }

    #[derive(FromArgs)]
    struct FieldSizeLimitArgs {
        #[pyarg(any, optional)]
        new_limit: OptionalArg<PyObjectRef>,
    }

    #[pyfunction]
    fn field_size_limit(args: FieldSizeLimitArgs, vm: &VirtualMachine) -> PyResult<isize> {
        let old_size = current_field_limit(vm)?;
        if let OptionalArg::Present(limit) = args.new_limit {
            let Ok(new_size) = limit.try_int(vm) else {
                return Err(vm.new_type_error("limit must be an integer"));
            };
            set_field_limit(vm, new_size.try_to_primitive::<isize>(vm)?)?;
        }
        Ok(old_size)
    }

    #[pyfunction]
    fn reader(iterable: PyIter, options: FormatOptions, vm: &VirtualMachine) -> PyResult<Reader> {
        let dialect = options.result(vm)?;
        Ok(Reader {
            iter: iterable,
            state: PyMutex::new(ReadState {
                line_num: 0,
                generation: 0,
            }),
            dialect,
        })
    }

    #[pyfunction]
    fn writer(
        fileobj: PyObjectRef,
        options: FormatOptions,
        vm: &VirtualMachine,
    ) -> PyResult<Writer> {
        let write = match vm.get_attribute_opt(&fileobj, "write")? {
            Some(write_meth) => write_meth,
            None if fileobj.is_callable() => fileobj,
            None => {
                return Err(vm.new_type_error(r#"argument 1 must have a "write" method"#));
            }
        };
        let dialect = options.result(vm)?;

        Ok(Writer { write, dialect })
    }

    #[repr(i32)]
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub enum QuoteStyle {
        Minimal = 0,
        All = 1,
        Nonnumeric = 2,
        None = 3,
        Strings = 4,
        Notnull = 5,
    }

    impl TryFromObject for QuoteStyle {
        fn try_from_object(vm: &VirtualMachine, obj: PyObjectRef) -> PyResult<Self> {
            let num = obj.try_int(vm)?.try_to_primitive::<isize>(vm)?;
            num.try_into().map_err(|_| {
                vm.new_value_error("can not convert to QuoteStyle enum from input argument")
            })
        }
    }

    impl TryFrom<isize> for QuoteStyle {
        type Error = ();

        fn try_from(num: isize) -> Result<Self, Self::Error> {
            Ok(match num {
                0 => Self::Minimal,
                1 => Self::All,
                2 => Self::Nonnumeric,
                3 => Self::None,
                4 => Self::Strings,
                5 => Self::Notnull,
                _ => return Err(()),
            })
        }
    }

    impl From<QuoteStyle> for isize {
        fn from(val: QuoteStyle) -> Self {
            match val {
                QuoteStyle::Minimal => 0,
                QuoteStyle::All => 1,
                QuoteStyle::Nonnumeric => 2,
                QuoteStyle::None => 3,
                QuoteStyle::Strings => 4,
                QuoteStyle::Notnull => 5,
            }
        }
    }

    #[derive(Default)]
    enum DialectItem {
        Str(String),
        Obj(PyDialect),
        #[default]
        None,
    }

    #[derive(Default)]
    struct FormatOptions {
        dialect: DialectItem,
        delimiter: Option<u8>,
        quotechar: Option<Option<u8>>,
        escapechar: Option<Option<u8>>,
        doublequote: Option<bool>,
        skipinitialspace: Option<bool>,
        lineterminator: Option<String>,
        quoting: Option<QuoteStyle>,
        strict: Option<bool>,
    }

    /// Resolve a named dialect or validate a dialect object.
    fn prase_dialect_item_from_arg(
        vm: &VirtualMachine,
        obj: PyObjectRef,
    ) -> Result<DialectItem, ArgumentError> {
        match_class!(match obj {
            s @ PyStr => {
                let s = s.try_into_utf8(vm).map_err(ArgumentError::Exception)?;
                Ok(DialectItem::Str(s.as_str().to_owned()))
            }
            PyNone => {
                Err(ArgumentError::InvalidKeywordArgument("dialect".to_string()))
            }
            t @ PyType => {
                let temp = t
                    .as_object()
                    .call(vec![], vm)
                    .map_err(ArgumentError::Exception)?;
                PyDialect::try_from_object(vm, temp)
                    .map(DialectItem::Obj)
                    .map_err(ArgumentError::Exception)
            }
            obj => PyDialect::try_from_object(vm, obj)
                .map(DialectItem::Obj)
                .map_err(ArgumentError::Exception),
        })
    }

    impl FromArgs for FormatOptions {
        const PARAMS: Option<&'static [Param]> = Some(&[
            Param {
                name: "dialect",
                kind: rustpython_vm::function::ParamKind::PositionalOrKeyword,
                default: Some(rustpython_vm::function::DefaultRepr::Str("excel")),
            },
            Param::var_keyword("fmtparams"),
        ]);

        fn from_args(vm: &VirtualMachine, args: &mut FuncArgs) -> Result<Self, ArgumentError> {
            let dialect = if let Some(dialect) = args.take_positional_keyword("dialect") {
                prase_dialect_item_from_arg(vm, dialect)?
            } else {
                DialectItem::None
            };

            let mut res = Self {
                dialect,
                ..Default::default()
            };

            if let Some(delimiter) = args.kwargs.swap_remove("delimiter") {
                res.delimiter = Some(parse_delimiter_from_obj(vm, &delimiter)?);
            }

            if let Some(escapechar) = args.kwargs.swap_remove("escapechar") {
                res.escapechar = match_class!(match escapechar {
                    s @ PyStr => Some(Some(parse_single_char(&s, vm, |_| {
                        vm.new_type_error(r#""escapechar" must be a 1-character string"#)
                    })?)),
                    PyNone => Some(None),
                    _ => {
                        return Err(ArgumentError::Exception(
                            vm.new_type_error(r#""escapechar" must be a 1-character string"#),
                        ));
                    }
                })
            };

            if let Some(lineterminator) = args.kwargs.swap_remove("lineterminator") {
                let s = lineterminator.downcast_ref::<PyStr>().ok_or_else(|| {
                    vm.new_type_error(format!(
                        r#""lineterminator" must be a string, not {}"#,
                        lineterminator.class().name()
                    ))
                })?;
                let value = parse_lineterminator(vm, s)?;
                res.lineterminator = Some(value.to_owned());
            };

            if let Some(doublequote) = args.kwargs.swap_remove("doublequote") {
                res.doublequote = Some(
                    doublequote
                        .try_to_bool(vm)
                        .map_err(|_| vm.new_type_error(r#""doublequote" must be a bool"#))?,
                )
            };

            if let Some(skipinitialspace) = args.kwargs.swap_remove("skipinitialspace") {
                res.skipinitialspace = Some(
                    skipinitialspace
                        .try_to_bool(vm)
                        .map_err(|_| vm.new_type_error(r#""skipinitialspace" must be a bool"#))?,
                )
            };

            if let Some(quoting) = args.kwargs.swap_remove("quoting") {
                res.quoting = match_class!(match quoting {
                    i @ PyInt =>
                        Some(i.try_to_primitive::<isize>(vm)?.try_into().map_err(|_e| {
                            ArgumentError::InvalidKeywordArgument("quoting".to_string())
                        })?),
                    _ => {
                        return Err(ArgumentError::InvalidKeywordArgument("quoting".to_string()));
                    }
                });
            };

            if let Some(quotechar) = args.kwargs.swap_remove("quotechar") {
                res.quotechar = match_class!(match quotechar {
                    s @ PyStr => Some(Some(parse_single_char(&s, vm, |_| {
                        vm.new_type_error(r#""quotechar" must be a 1-character string"#)
                    })?)),
                    PyNone => {
                        if res
                            .quoting
                            .is_some_and(|quoting| quoting != QuoteStyle::None)
                        {
                            return Err(ArgumentError::Exception(
                                vm.new_type_error("quotechar must be set if quoting enabled"),
                            ));
                        }
                        Some(None)
                    }
                    _o => {
                        return Err(
                            rustpython_vm::function::ArgumentError::InvalidKeywordArgument(
                                "quotechar".to_string(),
                            ),
                        );
                    }
                })
            };

            if let Some(strict) = args.kwargs.swap_remove("strict") {
                res.strict = Some(
                    strict
                        .try_to_bool(vm)
                        .map_err(|_| vm.new_type_error(r#""strict" must be a int enum"#))?,
                )
            };

            if let Some(last_arg) = args.kwargs.pop() {
                // The dialect is parsed by a parser of its own, which has no
                // name to give the message.
                return Err(ArgumentError::Exception(
                    vm.new_unexpected_keyword_type_error(None, &last_arg.0.to_string()),
                ));
            }

            Ok(res)
        }
    }

    fn validate_dialect(vm: &VirtualMachine, dialect: &PyDialect) -> PyResult<()> {
        let special = |name: &str, value: u8| {
            if matches!(value, b'\r' | b'\n') {
                Err(vm.new_value_error(format!(
                    "{name} must be a single character, not a line break"
                )))
            } else {
                Ok(())
            }
        };

        special("delimiter", dialect.delimiter)?;
        if let Some(quotechar) = dialect.quotechar {
            special("quotechar", quotechar)?;
        }
        if let Some(escapechar) = dialect.escapechar {
            special("escapechar", escapechar)?;
        }

        if dialect.skipinitialspace
            && (matches!(dialect.escapechar, Some(b' ')) || matches!(dialect.quotechar, Some(b' ')))
        {
            return Err(vm.new_value_error(
                "escapechar or quotechar cannot be a space when skipinitialspace is enabled",
            ));
        }

        let values: [(&str, Option<u8>); 3] = [
            ("delimiter", Some(dialect.delimiter)),
            ("quotechar", dialect.quotechar),
            ("escapechar", dialect.escapechar),
        ];
        for (index, (left_name, left)) in values.iter().enumerate() {
            for (right_name, right) in values.iter().skip(index + 1) {
                if left.is_some() && left == right {
                    return Err(vm.new_value_error(format!(
                        "{left_name} and {right_name} cannot be the same"
                    )));
                }
            }
            if left.is_some_and(|value| {
                dialect
                    .lineterminator
                    .chars()
                    .any(|character| character == value as char)
            }) {
                return Err(vm.new_value_error(format!(
                    "{left_name} and lineterminator cannot be the same"
                )));
            }
        }
        Ok(())
    }

    impl FormatOptions {
        fn update_py_dialect(&self, mut res: PyDialect) -> PyDialect {
            macro_rules! check_and_fill {
                ($res:ident, $e:ident) => {{
                    if let Some(t) = self.$e {
                        $res.$e = t;
                    }
                }};
            }

            check_and_fill!(res, delimiter);
            check_and_fill!(res, doublequote);
            check_and_fill!(res, skipinitialspace);

            if let Some(t) = self.escapechar {
                res.escapechar = t;
            };

            if let Some(t) = self.quotechar {
                res.quotechar = t;
            };

            check_and_fill!(res, quoting);
            if let Some(t) = &self.lineterminator {
                res.lineterminator.clone_from(t);
            };
            check_and_fill!(res, strict);
            res
        }

        fn result(&self, vm: &VirtualMachine) -> PyResult<PyDialect> {
            let dialect = match &self.dialect {
                DialectItem::Str(name) => with_dialects(vm, |dialects| {
                    if let Some(dialect) = dialects.get(name) {
                        Ok(self.update_py_dialect(dialect.clone()))
                    } else {
                        Err(new_csv_error(vm, format!("{name} is not registered.")))
                    }
                })?,
                DialectItem::Obj(o) => Ok(self.update_py_dialect(o.clone())),
                DialectItem::None => Ok(self.update_py_dialect(PyDialect {
                    delimiter: b',',
                    quotechar: Some(b'"'),
                    escapechar: None,
                    doublequote: true,
                    skipinitialspace: false,
                    lineterminator: "\r\n".to_owned(),
                    quoting: QuoteStyle::Minimal,
                    strict: false,
                })),
            }?;
            validate_dialect(vm, &dialect)?;
            Ok(dialect)
        }
    }

    struct ReadState {
        line_num: u64,
        generation: u64,
    }

    #[pyclass(no_attr, module = "_csv", name = "reader", traverse)]
    #[derive(PyPayload)]
    pub(super) struct Reader {
        iter: PyIter,
        #[pytraverse(skip)]
        state: PyMutex<ReadState>,
        #[pytraverse(skip)]
        dialect: PyDialect,
    }

    impl fmt::Debug for Reader {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "_csv.reader")
        }
    }

    #[pyclass(with(IterNext, Iterable), flags(DISALLOW_INSTANTIATION))]
    impl Reader {
        #[pygetset]
        fn line_num(zelf: &Py<Self>) -> u64 {
            zelf.state.lock().line_num
        }

        #[pygetset]
        fn dialect(zelf: &Py<Self>, _vm: &VirtualMachine) -> PyDialect {
            zelf.dialect.clone()
        }
    }

    impl SelfIter for Reader {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ParserState {
        StartRecord,
        StartField,
        EscapedChar,
        InField,
        InQuotedField,
        EscapeInQuotedField,
        QuoteInQuotedField,
        EatCrnl,
        AfterEscapedCrnl,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ParserInput {
        Byte(u8),
        Eol,
    }

    const EOL: ParserInput = ParserInput::Eol;

    struct CsvParser {
        state: ParserState,
        fields: Vec<PyObjectRef>,
        field: Vec<u8>,
        unquoted_field: bool,
        field_limit: isize,
    }

    impl CsvParser {
        fn new(field_limit: isize) -> Self {
            Self {
                state: ParserState::StartRecord,
                fields: Vec::new(),
                field: Vec::new(),
                unquoted_field: false,
                field_limit,
            }
        }

        fn into_result(self, vm: &VirtualMachine) -> PyIterReturn {
            PyIterReturn::Return(vm.ctx.new_list(self.fields).into())
        }

        fn add_byte(&mut self, byte: u8, vm: &VirtualMachine) -> PyResult<()> {
            if self.field_limit < 0 || self.field.len() >= self.field_limit as usize {
                return Err(new_csv_error(
                    vm,
                    format!("field larger than field limit ({})", self.field_limit),
                ));
            }
            self.field.push(byte);
            Ok(())
        }

        fn save_field(&mut self, quoting: QuoteStyle, vm: &VirtualMachine) -> PyResult<()> {
            let field = if self.unquoted_field
                && self.field.is_empty()
                && matches!(quoting, QuoteStyle::Notnull | QuoteStyle::Strings)
            {
                vm.ctx.none()
            } else {
                let value = core::str::from_utf8(&self.field)
                    .map_err(|e| new_not_utf8_error(vm, &self.field, e))?;
                let field: PyObjectRef = vm.ctx.new_str(value).into();
                if self.unquoted_field
                    && !self.field.is_empty()
                    && matches!(quoting, QuoteStyle::Nonnumeric | QuoteStyle::Strings)
                {
                    PyType::call(vm.ctx.types.float_type, vec![field].into(), vm)?
                } else {
                    field
                }
            };
            self.fields.push(field);
            self.field.clear();
            Ok(())
        }

        fn process_parser_input(
            &mut self,
            input: ParserInput,
            dialect: &PyDialect,
            vm: &VirtualMachine,
        ) -> PyResult<()> {
            match self.state {
                ParserState::StartRecord => match input {
                    ParserInput::Eol => {}
                    ParserInput::Byte(b'\r' | b'\n') => self.state = ParserState::EatCrnl,
                    _ => {
                        self.state = ParserState::StartField;
                        return self.process_parser_input(input, dialect, vm);
                    }
                },
                ParserState::StartField => {
                    self.unquoted_field = true;
                    match input {
                        ParserInput::Eol | ParserInput::Byte(b'\r' | b'\n') => {
                            self.save_field(dialect.quoting, vm)?;
                            self.state = state_after_record_end(input);
                        }
                        ParserInput::Byte(byte)
                            if dialect.quoting != QuoteStyle::None
                                && dialect.quotechar == Some(byte) =>
                        {
                            self.unquoted_field = false;
                            self.state = ParserState::InQuotedField;
                        }
                        ParserInput::Byte(byte) if dialect.escapechar == Some(byte) => {
                            self.state = ParserState::EscapedChar;
                        }
                        ParserInput::Byte(b' ') if dialect.skipinitialspace => {}
                        ParserInput::Byte(byte) if byte == dialect.delimiter => {
                            self.save_field(dialect.quoting, vm)?;
                        }
                        ParserInput::Byte(byte) => {
                            self.add_byte(byte, vm)?;
                            self.state = ParserState::InField;
                        }
                    }
                }
                ParserState::EscapedChar => match input {
                    ParserInput::Byte(byte @ (b'\r' | b'\n')) => {
                        self.add_byte(byte, vm)?;
                        self.state = ParserState::AfterEscapedCrnl;
                    }
                    ParserInput::Eol => {
                        self.add_byte(b'\n', vm)?;
                        self.state = ParserState::InField;
                    }
                    ParserInput::Byte(byte) => {
                        self.add_byte(byte, vm)?;
                        self.state = ParserState::InField;
                    }
                },
                ParserState::AfterEscapedCrnl => {
                    if input != ParserInput::Eol {
                        self.state = ParserState::InField;
                        return self.process_parser_input(input, dialect, vm);
                    }
                }
                ParserState::InField => match input {
                    ParserInput::Eol | ParserInput::Byte(b'\r' | b'\n') => {
                        self.save_field(dialect.quoting, vm)?;
                        self.state = state_after_record_end(input);
                    }
                    ParserInput::Byte(byte) if dialect.escapechar == Some(byte) => {
                        self.state = ParserState::EscapedChar;
                    }
                    ParserInput::Byte(byte) if byte == dialect.delimiter => {
                        self.save_field(dialect.quoting, vm)?;
                        self.state = ParserState::StartField;
                    }
                    ParserInput::Byte(byte) => self.add_byte(byte, vm)?,
                },
                ParserState::InQuotedField => match input {
                    ParserInput::Eol => {}
                    ParserInput::Byte(byte) if dialect.escapechar == Some(byte) => {
                        self.state = ParserState::EscapeInQuotedField;
                    }
                    ParserInput::Byte(byte)
                        if dialect.quoting != QuoteStyle::None
                            && dialect.quotechar == Some(byte) =>
                    {
                        self.state = if dialect.doublequote {
                            ParserState::QuoteInQuotedField
                        } else {
                            ParserState::InField
                        };
                    }
                    ParserInput::Byte(byte) => self.add_byte(byte, vm)?,
                },
                ParserState::EscapeInQuotedField => {
                    let byte = match input {
                        ParserInput::Eol => b'\n',
                        ParserInput::Byte(byte) => byte,
                    };
                    self.add_byte(byte, vm)?;
                    self.state = ParserState::InQuotedField;
                }
                ParserState::QuoteInQuotedField => match input {
                    ParserInput::Byte(byte)
                        if dialect.quoting != QuoteStyle::None
                            && dialect.quotechar == Some(byte) =>
                    {
                        self.add_byte(byte, vm)?;
                        self.state = ParserState::InQuotedField;
                    }
                    ParserInput::Byte(byte) if byte == dialect.delimiter => {
                        self.save_field(dialect.quoting, vm)?;
                        self.state = ParserState::StartField;
                    }
                    ParserInput::Eol | ParserInput::Byte(b'\r' | b'\n') => {
                        self.save_field(dialect.quoting, vm)?;
                        self.state = state_after_record_end(input);
                    }
                    ParserInput::Byte(byte) if !dialect.strict => {
                        self.add_byte(byte, vm)?;
                        self.state = ParserState::InField;
                    }
                    ParserInput::Byte(_) => {
                        return Err(new_csv_error(
                            vm,
                            format!(
                                "'{}' expected after '{}'",
                                dialect.delimiter as char,
                                dialect.quotechar.unwrap_or_default() as char,
                            ),
                        ));
                    }
                },
                ParserState::EatCrnl => match input {
                    ParserInput::Byte(b'\r' | b'\n') => {}
                    ParserInput::Eol => self.state = ParserState::StartRecord,
                    ParserInput::Byte(_) => {
                        return Err(new_csv_error(
                            vm,
                            concat!(
                                "new-line character seen in unquoted field - ",
                                "do you need to open the file with newline=''?"
                            ),
                        ));
                    }
                },
            }
            Ok(())
        }
    }

    fn state_after_record_end(input: ParserInput) -> ParserState {
        if input == ParserInput::Eol {
            ParserState::StartRecord
        } else {
            ParserState::EatCrnl
        }
    }

    fn next_input_item(zelf: &Py<Reader>, vm: &VirtualMachine) -> PyResult<PyIterReturn> {
        let generation = zelf.state.lock().generation;
        // Advancing user code may re-enter this reader, so do not hold its lock here.
        let result = zelf.iter.next(vm)?;
        let mut state = zelf.state.lock();
        if state.generation != generation {
            return Err(new_csv_error(
                vm,
                "iterator has already advanced the reader",
            ));
        }
        if matches!(result, PyIterReturn::Return(_)) {
            state.generation += 1;
        }
        Ok(result)
    }

    fn finish_at_true_eof(
        mut parser: CsvParser,
        dialect: &PyDialect,
        vm: &VirtualMachine,
    ) -> PyResult<PyIterReturn> {
        let has_unfinished_record =
            !parser.field.is_empty() || parser.state == ParserState::InQuotedField;
        if !has_unfinished_record {
            return Ok(PyIterReturn::StopIteration(None));
        }
        if dialect.strict {
            return Err(new_csv_error(vm, "unexpected end of data"));
        }
        parser.save_field(dialect.quoting, vm)?;
        Ok(parser.into_result(vm))
    }

    impl IterNext for Reader {
        fn next(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyIterReturn> {
            let mut parser = CsvParser::new(current_field_limit(vm)?);

            loop {
                match next_input_item(zelf, vm)? {
                    PyIterReturn::Return(obj) => {
                        let string = obj.downcast::<PyStr>().map_err(|obj| {
                            new_csv_error(
                                vm,
                                format!(
                                    concat!(
                                        "iterator should return strings, not {} ",
                                        "(the file should be opened in text mode)"
                                    ),
                                    obj.class().name()
                                ),
                            )
                        })?;

                        zelf.state.lock().line_num += 1;
                        parser.field_limit = current_field_limit(vm)?;
                        for &byte in string.as_bytes() {
                            parser.process_parser_input(
                                ParserInput::Byte(byte),
                                &zelf.dialect,
                                vm,
                            )?;
                        }

                        // Virtual EOL marks an iterator-item boundary, not true EOF.
                        parser.process_parser_input(EOL, &zelf.dialect, vm)?;
                        if parser.state == ParserState::StartRecord {
                            return Ok(parser.into_result(vm));
                        }
                    }
                    PyIterReturn::StopIteration(_) => {
                        return finish_at_true_eof(parser, &zelf.dialect, vm);
                    }
                }
            }
        }
    }

    #[pyclass(no_attr, module = "_csv", name = "writer", traverse)]
    #[derive(PyPayload)]
    pub(super) struct Writer {
        write: PyObjectRef,
        #[pytraverse(skip)]
        dialect: PyDialect,
    }

    impl fmt::Debug for Writer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "_csv.writer")
        }
    }

    fn write_quoted_field(
        output: &mut Vec<u8>,
        data: &[u8],
        dialect: &PyDialect,
        vm: &VirtualMachine,
    ) -> PyResult<()> {
        let quotechar = dialect
            .quotechar
            .ok_or_else(|| vm.new_type_error("quotechar must be set if quoting enabled"))?;
        output.push(quotechar);
        for &byte in data {
            if byte == quotechar {
                if dialect.doublequote {
                    output.push(quotechar);
                    output.push(quotechar);
                } else if let Some(escapechar) = dialect.escapechar {
                    output.push(escapechar);
                    output.push(byte);
                } else {
                    return Err(new_csv_error(vm, "need to escape, but no escapechar set"));
                }
            } else {
                if dialect.escapechar == Some(byte) {
                    output.push(byte);
                }
                output.push(byte);
            }
        }
        output.push(quotechar);
        Ok(())
    }

    fn write_unquoted_field(
        output: &mut Vec<u8>,
        data: &[u8],
        dialect: &PyDialect,
        vm: &VirtualMachine,
    ) -> PyResult<()> {
        let mut data = data;
        while let Some((&byte, rest)) = data.split_first() {
            if field_needs_escape(data, dialect) {
                let escapechar = dialect
                    .escapechar
                    .ok_or_else(|| new_csv_error(vm, "need to escape, but no escapechar set"))?;
                output.push(escapechar);
            }
            output.push(byte);
            data = rest;
        }
        Ok(())
    }

    fn data_contains_lineterminator_char(data: &[u8], dialect: &PyDialect) -> bool {
        dialect.lineterminator.chars().any(|character| {
            let mut encoded = [0; 4];
            let character = character.encode_utf8(&mut encoded).as_bytes();
            data.windows(character.len())
                .any(|window| window == character)
        })
    }

    fn data_starts_with_lineterminator_char(data: &[u8], dialect: &PyDialect) -> bool {
        dialect.lineterminator.chars().any(|character| {
            let mut encoded = [0; 4];
            let character = character.encode_utf8(&mut encoded).as_bytes();
            data.starts_with(character)
        })
    }

    fn field_needs_quotes(data: &[u8], dialect: &PyDialect) -> bool {
        data.iter().any(|&byte| {
            byte == dialect.delimiter
                || dialect.quotechar == Some(byte)
                || matches!(byte, b'\r' | b'\n')
        }) || data_contains_lineterminator_char(data, dialect)
    }

    fn field_needs_escape(data: &[u8], dialect: &PyDialect) -> bool {
        let byte = data[0];
        byte == dialect.delimiter
            || dialect.quotechar == Some(byte)
            || dialect.escapechar == Some(byte)
            || matches!(byte, b'\r' | b'\n')
            || data_starts_with_lineterminator_char(data, dialect)
    }

    fn write_lineterminator(output: &mut Vec<u8>, terminator: &str) {
        output.extend_from_slice(terminator.as_bytes());
    }

    #[pyclass(flags(DISALLOW_INSTANTIATION))]
    impl Writer {
        #[pygetset(name = "dialect")]
        fn get_dialect(zelf: &Py<Self>, _vm: &VirtualMachine) -> PyDialect {
            zelf.dialect.clone()
        }

        #[pymethod]
        fn writerow(zelf: &Py<Self>, row: PyObjectRef, vm: &VirtualMachine) -> PyResult {
            let row: ArgIterable =
                ArgIterable::try_from_object(vm, row.to_owned()).map_err(|_e| {
                    new_csv_error(
                        vm,
                        format!("'{}' object is not iterable", row.class().name()),
                    )
                })?;
            let fields = row.iter(vm)?.collect::<PyResult<Vec<_>>>()?;
            let single_field = fields.len() == 1;
            let mut output = Vec::new();

            for (index, field) in fields.into_iter().enumerate() {
                if index > 0 {
                    output.push(zelf.dialect.delimiter);
                }

                let stringified;
                let (data, is_str, is_none): (&[u8], bool, bool) = match_class!(match field {
                    ref s @ PyStr => (s.as_bytes(), true, false),
                    PyNone => (b"", false, true),
                    ref obj => {
                        stringified = obj.str(vm)?;
                        (stringified.as_bytes(), false, false)
                    }
                });

                if single_field
                    && data.is_empty()
                    && (zelf.dialect.quoting == QuoteStyle::None
                        || (is_none
                            && matches!(
                                zelf.dialect.quoting,
                                QuoteStyle::Strings | QuoteStyle::Notnull
                            )))
                {
                    return Err(new_csv_error(
                        vm,
                        "single empty field record must be quoted",
                    ));
                }

                if data.is_empty()
                    && zelf.dialect.delimiter == b' '
                    && zelf.dialect.skipinitialspace
                    && (zelf.dialect.quoting == QuoteStyle::None
                        || (is_none
                            && matches!(
                                zelf.dialect.quoting,
                                QuoteStyle::Strings | QuoteStyle::Notnull
                            )))
                {
                    return Err(new_csv_error(
                        vm,
                        "empty field must be quoted if delimiter is a space and skipinitialspace is true",
                    ));
                }

                let mut should_quote = match zelf.dialect.quoting {
                    QuoteStyle::All => true,
                    QuoteStyle::Nonnumeric => !PyNumber::check(&field),
                    QuoteStyle::Strings => is_str,
                    QuoteStyle::Notnull => !is_none,
                    QuoteStyle::Minimal | QuoteStyle::None => false,
                };

                if zelf.dialect.quoting != QuoteStyle::None
                    && ((data.is_empty()
                        && zelf.dialect.delimiter == b' '
                        && zelf.dialect.skipinitialspace)
                        || (single_field && data.is_empty())
                        || (!should_quote && field_needs_quotes(data, &zelf.dialect)))
                {
                    should_quote = true;
                }

                if should_quote {
                    write_quoted_field(&mut output, data, &zelf.dialect, vm)?;
                } else {
                    write_unquoted_field(&mut output, data, &zelf.dialect, vm)?;
                }
            }

            write_lineterminator(&mut output, &zelf.dialect.lineterminator);
            let s =
                core::str::from_utf8(&output).map_err(|e| new_not_utf8_error(vm, &output, e))?;
            zelf.write.call((s,), vm)
        }

        #[pymethod]
        fn writerows(zelf: &Py<Self>, rows: ArgIterable, vm: &VirtualMachine) -> PyResult<()> {
            for row in rows.iter(vm)? {
                Self::writerow(zelf, row?, vm)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use rustpython_vm::{Interpreter, Settings};

    fn interpreter() -> Interpreter {
        let mut settings = Settings::default();
        settings.path_list.clear();
        settings.ignore_environment = true;
        settings.isolated = true;
        settings.install_signal_handlers = false;
        settings.import_site = false;
        Interpreter::with_init(settings, |vm| {
            let definition = super::module_def(&vm.ctx);
            std::rc::Rc::get_mut(&mut vm.state)
                .expect("the initialization hook owns the new VM state")
                .module_defs
                .insert("_csv", definition);
        })
    }

    fn run(interpreter: &Interpreter, source: &str) {
        interpreter.enter_and_expect(
            |vm| vm.run_code_string(vm.new_scope_with_builtins(), source, "<windows-csv-test>"),
            "Windows CSV state check",
        );
    }

    #[test]
    fn interpreters_on_one_host_thread_keep_independent_csv_state() {
        let first = interpreter();
        let second = interpreter();
        run(
            &first,
            r#"
import _csv
_csv.register_dialect('first', delimiter='|', lineterminator='A' * 4096)
_csv.field_size_limit(17)
"#,
        );
        run(
            &second,
            r#"
import _csv
assert _csv.list_dialects() == []
assert _csv.field_size_limit() == 131072
_csv.register_dialect('second', delimiter=';')
_csv.field_size_limit(29)
"#,
        );
        // A later entry into the same environment retains its registry and limit.
        run(
            &first,
            r#"
import _csv
assert _csv.list_dialects() == ['first']
assert _csv.field_size_limit() == 17
assert _csv.get_dialect('first').lineterminator == 'A' * 4096
assert next(_csv.reader(['a|b'], dialect='first')) == ['a', 'b']
try:
    next(_csv.reader(['x' * 18]))
except _csv.Error:
    pass
else:
    raise AssertionError('the reader must use its own environment field limit')
_csv.unregister_dialect('first')
assert _csv.list_dialects() == []
"#,
        );
        run(
            &second,
            r#"
import _csv
assert _csv.list_dialects() == ['second']
assert _csv.field_size_limit() == 29
assert next(_csv.reader(['x' * 18])) == ['x' * 18]
"#,
        );
        first.finalize(None);
        second.finalize(None);
        let fresh = interpreter();
        run(
            &fresh,
            "import _csv\nassert _csv.list_dialects() == []\nassert _csv.field_size_limit() == 131072",
        );
        fresh.finalize(None);
    }

    #[test]
    fn corrupted_module_state_fails_without_using_shared_storage() {
        let interpreter = interpreter();
        run(
            &interpreter,
            r#"
import _csv
_csv.register_dialect('held', delimiter='|')
state = _csv._state
try:
    type(state)()
except TypeError:
    pass
else:
    raise AssertionError('CSV state must not be constructible by guest code')
_csv._state = object()
for operation in (_csv.list_dialects, _csv.field_size_limit):
    try:
        operation()
    except RuntimeError:
        pass
    else:
        raise AssertionError('corrupted CSV state must not fall back to shared storage')
_csv._state = state
assert _csv.list_dialects() == ['held']
"#,
        );
        interpreter.finalize(None);
    }
}
