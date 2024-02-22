/***************************************************************************
* Copyright (c) 2018, Martin Renou, Johan Mabille, Sylvain Corlay, and     *
* Wolf Vollprecht                                                          *
* Copyright (c) 2018, QuantStack                                           *
*                                                                          *
* Distributed under the terms of the BSD 3-Clause License.                 *
*                                                                          *
* The full license is in the file LICENSE, distributed with this software. *
****************************************************************************/

#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <signal.h>
#include <functional> // std::function

#ifdef __GNUC__
#include <stdio.h>
#include <execinfo.h>
#include <stdlib.h>
#include <unistd.h>
#endif

#include "xeus/xeus_context.hpp"
#include "xeus/xkernel.hpp"
#include "xeus/xkernel_configuration.hpp"
#include "xeus/xinterpreter.hpp"

#include "xeus-zmq/xserver_zmq.hpp"

// REMOVE
#define UVW_AS_LIB
#include <uvw.hpp>

#include "pybind11/embed.h"
#include "pybind11/pybind11.h"

#include "xeus-python/xinterpreter.hpp"
#include "xeus-python/xinterpreter_raw.hpp"
#include "xeus-python/xdebugger.hpp"
#include "xeus-python/xpaths.hpp"
#include "xeus-python/xeus_python_config.hpp"
#include "xeus-python/xutils.hpp"

namespace py = pybind11;

// Global variable to hold the lambda state
std::function<std::unique_ptr<xeus::xserver>(xeus::xcontext&, const xeus::xconfiguration&, nl::json::error_handler_t)> make_uv_server_holder;

// The callback to create the server
std::unique_ptr<xeus::xserver> make_uv_server(
    xeus::xcontext& context, const xeus::xconfiguration& config, nl::json::error_handler_t eh)
{
    return make_uv_server_holder(context, config, eh);
}


int main(int argc, char* argv[])
{
    if (xpyt::should_print_version(argc, argv))
    {
        std::clog << "xpython " << XPYT_VERSION << std::endl;
        return 0;
    }

    // If we are called from the Jupyter launcher, silence all logging. This
    // is important for a JupyterHub configured with cleanup_servers = False:
    // Upon restart, spawned single-user servers keep running but without the
    // std* streams. When a user then tries to start a new kernel, xpython
    // will get a SIGPIPE and exit.
    if (std::getenv("JPY_PARENT_PID") != NULL)
    {
        std::clog.setstate(std::ios_base::failbit);
    }

    // Registering SIGSEGV handler
#ifdef __GNUC__
    std::clog << "registering handler for SIGSEGV" << std::endl;
    signal(SIGSEGV, xpyt::sigsegv_handler);

    // Registering SIGINT and SIGKILL handlers
    signal(SIGKILL, xpyt::sigkill_handler);
#endif
    signal(SIGINT, xpyt::sigkill_handler);

    // Setting Program Name
    static const std::string executable(xpyt::get_python_path());
    static const std::wstring wexecutable(executable.cbegin(), executable.cend());

    // On windows, sys.executable is not properly set with Py_SetProgramName
    // Cf. https://bugs.python.org/issue34725
    // A private undocumented API was added as a workaround in Python 3.7.2.
    // _Py_SetProgramFullPath(const_cast<wchar_t*>(wexecutable.c_str()));
    Py_SetProgramName(const_cast<wchar_t*>(wexecutable.c_str()));

    // Setting PYTHONHOME
    xpyt::set_pythonhome();
    xpyt::print_pythonhome();

    // Instantiating the Python interpreter
    py::scoped_interpreter guard;

    py::gil_scoped_acquire acquire;

    // Instantiating the loop manually
    py::exec(R"(
        import asyncio
        import uvloop
        from uvloop.loop import libuv_get_loop_t_ptr

        loop = uvloop.new_event_loop()
        asyncio.set_event_loop(loop)
    )");

    py::object py_loop_ptr = py::eval("libuv_get_loop_t_ptr(loop)");
    void* raw_ptr = PyCapsule_GetPointer(py_loop_ptr.ptr(), nullptr);
    if (raw_ptr == nullptr)
    {
        throw std::runtime_error("Failed to get loop pointer");
    }
    auto uv_loop_ptr = static_cast<uv_loop_t*>(raw_ptr);
    auto loop_ptr = uvw::loop::create(uv_loop_ptr);

    // std::cout << "LOOP is alive: " << (loop_ptr->alive() ? "yes\n" : "no\n");

    // Setting argv
    wchar_t** argw = new wchar_t*[size_t(argc)];
    for(auto i = 0; i < argc; ++i)
    {
        argw[i] = Py_DecodeLocale(argv[i], nullptr);
    }
    PySys_SetArgvEx(argc, argw, 0);
    for(auto i = 0; i < argc; ++i)
    {
        PyMem_RawFree(argw[i]);
    }
    delete[] argw;

    using context_type = xeus::xcontext_impl<zmq::context_t>;
    using context_ptr = std::unique_ptr<context_type>;
    context_ptr context = context_ptr(new context_type());

    // Instantiating the xeus xinterpreter
    bool raw_mode = xpyt::extract_option("-r", "--raw", argc, argv);
    using interpreter_ptr = std::unique_ptr<xeus::xinterpreter>;
    interpreter_ptr interpreter;
    if (raw_mode)
    {
        interpreter = interpreter_ptr(new xpyt::raw_interpreter());
    }
    else
    {
        interpreter = interpreter_ptr(new xpyt::interpreter());
    }

    using history_manager_ptr = std::unique_ptr<xeus::xhistory_manager>;
    history_manager_ptr hist = xeus::make_in_memory_history_manager();

    std::string connection_filename = xpyt::extract_parameter("-f", argc, argv);

#ifdef XEUS_PYTHON_PYPI_WARNING
    std::clog <<
        "WARNING: this instance of xeus-python has been installed from a PyPI wheel.\n"
        "We recommend using a general-purpose package manager instead, such as Conda/Mamba.\n"
        << std::endl;
#endif

    nl::json debugger_config;
    debugger_config["python"] = executable;

    // the global variable make_uv_server_holder is set to a lambda that captures the loop_ptr
    make_uv_server_holder = [loop_ptr](
        xeus::xcontext& context, const xeus::xconfiguration& config, nl::json::error_handler_t eh)
        -> std::unique_ptr<xeus::xserver>
    {
        return xeus::make_xserver_uv_shell_main(context, config, eh, loop_ptr);
    };

    if (!connection_filename.empty())
    {
        xeus::xconfiguration config = xeus::load_configuration(connection_filename);

        xeus::xkernel kernel(config,
                             xeus::get_user_name(),
                             std::move(context),
                             std::move(interpreter),
                             make_uv_server,
                             std::move(hist),
                             xeus::make_console_logger(xeus::xlogger::msg_type,
                                                       xeus::make_file_logger(xeus::xlogger::content, "xeus.log")));
                            //  xpyt::make_python_debugger,
                            //  debugger_config);

        std::clog <<
            "Starting xeus-python kernel...\n\n"
            "If you want to connect to this kernel from an other client, you can use"
            " the " + connection_filename + " file."
            << std::endl;

        kernel.start();
    }
    else
    {
        xeus::xkernel kernel(xeus::get_user_name(),
                             std::move(context),
                             std::move(interpreter),
                             make_uv_server,
                             std::move(hist));
                            //  xpyt::make_python_debugger,
                            //  debugger_config);

        const auto& config = kernel.get_config();
        std::clog <<
            "Starting xeus-python kernel...\n\n"
            "If you want to connect to this kernel from an other client, just copy"
            " and paste the following content inside of a `kernel.json` file. And then run for example:\n\n"
            "# jupyter console --existing kernel.json\n\n"
            "kernel.json\n```\n{\n"
            "    \"transport\": \"" + config.m_transport + "\",\n"
            "    \"ip\": \"" + config.m_ip + "\",\n"
            "    \"control_port\": " + config.m_control_port + ",\n"
            "    \"shell_port\": " + config.m_shell_port + ",\n"
            "    \"stdin_port\": " + config.m_stdin_port + ",\n"
            "    \"iopub_port\": " + config.m_iopub_port + ",\n"
            "    \"hb_port\": " + config.m_hb_port + ",\n"
            "    \"signature_scheme\": \"" + config.m_signature_scheme + "\",\n"
            "    \"key\": \"" + config.m_key + "\"\n"
            "}\n```"
            << std::endl;

        kernel.start();
    }

    // Call python to start event loop
    py::exec("loop.run_forever()");

    return 0;
}
