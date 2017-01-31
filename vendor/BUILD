package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_binary",
    "go_library",
)

go_library(
    name = "github.com/Sirupsen/logrus",
    srcs = [
        "github.com/Sirupsen/logrus/alt_exit.go",
        "github.com/Sirupsen/logrus/doc.go",
        "github.com/Sirupsen/logrus/entry.go",
        "github.com/Sirupsen/logrus/exported.go",
        "github.com/Sirupsen/logrus/formatter.go",
        "github.com/Sirupsen/logrus/hooks.go",
        "github.com/Sirupsen/logrus/json_formatter.go",
        "github.com/Sirupsen/logrus/logger.go",
        "github.com/Sirupsen/logrus/logrus.go",
        "github.com/Sirupsen/logrus/terminal_linux.go",
        "github.com/Sirupsen/logrus/terminal_notwindows.go",
        "github.com/Sirupsen/logrus/text_formatter.go",
        "github.com/Sirupsen/logrus/writer.go",
    ],
    tags = ["automanaged"],
)

go_binary(
    name = "github.com/Sirupsen/logrus/examples/basic_bin",
    library = ":github.com/Sirupsen/logrus/examples/basic",
    tags = ["automanaged"],
)

go_library(
    name = "github.com/Sirupsen/logrus/examples/basic",
    srcs = ["github.com/Sirupsen/logrus/examples/basic/basic.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/Sirupsen/logrus"],
)

go_binary(
    name = "github.com/Sirupsen/logrus/examples/hook_bin",
    library = ":github.com/Sirupsen/logrus/examples/hook",
    tags = ["automanaged"],
)

go_library(
    name = "github.com/Sirupsen/logrus/examples/hook",
    srcs = ["github.com/Sirupsen/logrus/examples/hook/hook.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/Sirupsen/logrus",
        "//vendor:gopkg.in/gemnasium/logrus-airbrake-hook.v2",
    ],
)

go_library(
    name = "github.com/Sirupsen/logrus/hooks/syslog",
    srcs = ["github.com/Sirupsen/logrus/hooks/syslog/syslog.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/Sirupsen/logrus"],
)

go_library(
    name = "github.com/Sirupsen/logrus/hooks/test",
    srcs = ["github.com/Sirupsen/logrus/hooks/test/test.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/Sirupsen/logrus"],
)

go_library(
    name = "github.com/jessevdk/go-flags",
    srcs = [
        "github.com/jessevdk/go-flags/arg.go",
        "github.com/jessevdk/go-flags/closest.go",
        "github.com/jessevdk/go-flags/command.go",
        "github.com/jessevdk/go-flags/completion.go",
        "github.com/jessevdk/go-flags/convert.go",
        "github.com/jessevdk/go-flags/error.go",
        "github.com/jessevdk/go-flags/flags.go",
        "github.com/jessevdk/go-flags/group.go",
        "github.com/jessevdk/go-flags/help.go",
        "github.com/jessevdk/go-flags/ini.go",
        "github.com/jessevdk/go-flags/man.go",
        "github.com/jessevdk/go-flags/multitag.go",
        "github.com/jessevdk/go-flags/option.go",
        "github.com/jessevdk/go-flags/optstyle_other.go",
        "github.com/jessevdk/go-flags/parser.go",
        "github.com/jessevdk/go-flags/termsize.go",
        "github.com/jessevdk/go-flags/termsize_linux.go",
    ],
    tags = ["automanaged"],
)

go_binary(
    name = "github.com/jessevdk/go-flags/examples_bin",
    library = ":github.com/jessevdk/go-flags/examples",
    tags = ["automanaged"],
)

go_library(
    name = "github.com/jessevdk/go-flags/examples",
    srcs = [
        "github.com/jessevdk/go-flags/examples/add.go",
        "github.com/jessevdk/go-flags/examples/main.go",
        "github.com/jessevdk/go-flags/examples/rm.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/jessevdk/go-flags"],
)

go_library(
    name = "golang.org/x/sys/unix",
    srcs = [
        "golang.org/x/sys/unix/asm.s",
        "golang.org/x/sys/unix/asm_linux_amd64.s",
        "golang.org/x/sys/unix/bluetooth_linux.go",
        "golang.org/x/sys/unix/constants.go",
        "golang.org/x/sys/unix/env_unix.go",
        "golang.org/x/sys/unix/env_unset.go",
        "golang.org/x/sys/unix/flock.go",
        "golang.org/x/sys/unix/race0.go",
        "golang.org/x/sys/unix/sockcmsg_linux.go",
        "golang.org/x/sys/unix/sockcmsg_unix.go",
        "golang.org/x/sys/unix/str.go",
        "golang.org/x/sys/unix/syscall.go",
        "golang.org/x/sys/unix/syscall_linux.go",
        "golang.org/x/sys/unix/syscall_linux_amd64.go",
        "golang.org/x/sys/unix/syscall_linux_amd64_gc.go",
        "golang.org/x/sys/unix/syscall_unix.go",
        "golang.org/x/sys/unix/syscall_unix_gc.go",
        "golang.org/x/sys/unix/zerrors_linux_amd64.go",
        "golang.org/x/sys/unix/zsyscall_linux_amd64.go",
        "golang.org/x/sys/unix/zsysnum_linux_amd64.go",
        "golang.org/x/sys/unix/ztypes_linux_amd64.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "gopkg.in/airbrake/gobrake.v2",
    srcs = [
        "gopkg.in/airbrake/gobrake.v2/gobrake.go",
        "gopkg.in/airbrake/gobrake.v2/notice.go",
        "gopkg.in/airbrake/gobrake.v2/notifier.go",
        "gopkg.in/airbrake/gobrake.v2/util.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "gopkg.in/gemnasium/logrus-airbrake-hook.v2",
    srcs = ["gopkg.in/gemnasium/logrus-airbrake-hook.v2/airbrake.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/Sirupsen/logrus",
        "//vendor:gopkg.in/airbrake/gobrake.v2",
    ],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
)
