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

go_library(
    name = "cloud.google.com/go/compute/metadata",
    srcs = ["cloud.google.com/go/compute/metadata/metadata.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:cloud.google.com/go/internal",
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/net/context/ctxhttp",
    ],
)

go_library(
    name = "cloud.google.com/go/internal",
    srcs = [
        "cloud.google.com/go/internal/cloud.go",
        "cloud.google.com/go/internal/retry.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/googleapis/gax-go",
        "//vendor:golang.org/x/net/context",
    ],
)

go_library(
    name = "cloud.google.com/go/internal/atomiccache",
    srcs = ["cloud.google.com/go/internal/atomiccache/atomiccache.go"],
    tags = ["automanaged"],
)

go_library(
    name = "cloud.google.com/go/internal/fields",
    srcs = [
        "cloud.google.com/go/internal/fields/fields.go",
        "cloud.google.com/go/internal/fields/fold.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor:cloud.google.com/go/internal/atomiccache"],
)

go_library(
    name = "cloud.google.com/go/internal/optional",
    srcs = ["cloud.google.com/go/internal/optional/optional.go"],
    tags = ["automanaged"],
)

go_library(
    name = "cloud.google.com/go/internal/pretty",
    srcs = [
        "cloud.google.com/go/internal/pretty/diff.go",
        "cloud.google.com/go/internal/pretty/pretty.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "cloud.google.com/go/internal/testutil",
    srcs = [
        "cloud.google.com/go/internal/testutil/context.go",
        "cloud.google.com/go/internal/testutil/server.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/oauth2",
        "//vendor:golang.org/x/oauth2/google",
        "//vendor:google.golang.org/grpc",
    ],
)

go_library(
    name = "cloud.google.com/go/internal/version",
    srcs = ["cloud.google.com/go/internal/version/version.go"],
    tags = ["automanaged"],
)

go_library(
    name = "github.com/golang/glog",
    srcs = [
        "github.com/golang/glog/glog.go",
        "github.com/golang/glog/glog_file.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "github.com/golang/protobuf/proto",
    srcs = [
        "github.com/golang/protobuf/proto/clone.go",
        "github.com/golang/protobuf/proto/decode.go",
        "github.com/golang/protobuf/proto/encode.go",
        "github.com/golang/protobuf/proto/equal.go",
        "github.com/golang/protobuf/proto/extensions.go",
        "github.com/golang/protobuf/proto/lib.go",
        "github.com/golang/protobuf/proto/message_set.go",
        "github.com/golang/protobuf/proto/pointer_unsafe.go",
        "github.com/golang/protobuf/proto/properties.go",
        "github.com/golang/protobuf/proto/text.go",
        "github.com/golang/protobuf/proto/text_parser.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "github.com/golang/protobuf/proto/proto3_proto",
    srcs = ["github.com/golang/protobuf/proto/proto3_proto/proto3.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:github.com/golang/protobuf/proto/testdata",
        "//vendor:github.com/golang/protobuf/ptypes/any",
    ],
)

go_library(
    name = "github.com/golang/protobuf/protoc-gen-go/descriptor",
    srcs = ["github.com/golang/protobuf/protoc-gen-go/descriptor/descriptor.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "github.com/golang/protobuf/ptypes/any",
    srcs = ["github.com/golang/protobuf/ptypes/any/any.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "github.com/googleapis/gax-go",
    srcs = [
        "github.com/googleapis/gax-go/call_option.go",
        "github.com/googleapis/gax-go/gax.go",
        "github.com/googleapis/gax-go/invoke.go",
        "github.com/googleapis/gax-go/path_template.go",
        "github.com/googleapis/gax-go/path_template_parser.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/codes",
    ],
)

go_library(
    name = "go4.org/syncutil/singleflight",
    srcs = ["go4.org/syncutil/singleflight/singleflight.go"],
    tags = ["automanaged"],
)

go_library(
    name = "golang.org/x/crypto/acme",
    srcs = [
        "golang.org/x/crypto/acme/acme.go",
        "golang.org/x/crypto/acme/jws.go",
        "golang.org/x/crypto/acme/types.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/net/context/ctxhttp",
    ],
)

go_library(
    name = "golang.org/x/crypto/acme/autocert",
    srcs = [
        "golang.org/x/crypto/acme/autocert/autocert.go",
        "golang.org/x/crypto/acme/autocert/cache.go",
        "golang.org/x/crypto/acme/autocert/renewal.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/crypto/acme",
        "//vendor:golang.org/x/net/context",
    ],
)

go_library(
    name = "golang.org/x/crypto/ssh/terminal",
    srcs = [
        "golang.org/x/crypto/ssh/terminal/terminal.go",
        "golang.org/x/crypto/ssh/terminal/util.go",
        "golang.org/x/crypto/ssh/terminal/util_linux.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "golang.org/x/net/context",
    srcs = [
        "golang.org/x/net/context/context.go",
        "golang.org/x/net/context/go17.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "golang.org/x/net/context/ctxhttp",
    srcs = ["golang.org/x/net/context/ctxhttp/ctxhttp.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/net/context"],
)

go_library(
    name = "golang.org/x/net/http2",
    srcs = [
        "golang.org/x/net/http2/client_conn_pool.go",
        "golang.org/x/net/http2/configure_transport.go",
        "golang.org/x/net/http2/errors.go",
        "golang.org/x/net/http2/fixed_buffer.go",
        "golang.org/x/net/http2/flow.go",
        "golang.org/x/net/http2/frame.go",
        "golang.org/x/net/http2/go16.go",
        "golang.org/x/net/http2/go17.go",
        "golang.org/x/net/http2/go17_not18.go",
        "golang.org/x/net/http2/gotrack.go",
        "golang.org/x/net/http2/headermap.go",
        "golang.org/x/net/http2/http2.go",
        "golang.org/x/net/http2/not_go18.go",
        "golang.org/x/net/http2/pipe.go",
        "golang.org/x/net/http2/server.go",
        "golang.org/x/net/http2/transport.go",
        "golang.org/x/net/http2/write.go",
        "golang.org/x/net/http2/writesched.go",
        "golang.org/x/net/http2/writesched_priority.go",
        "golang.org/x/net/http2/writesched_random.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/http2/hpack",
        "//vendor:golang.org/x/net/idna",
        "//vendor:golang.org/x/net/lex/httplex",
    ],
)

go_binary(
    name = "golang.org/x/net/http2/h2i_bin",
    library = ":golang.org/x/net/http2/h2i",
    tags = ["automanaged"],
)

go_library(
    name = "golang.org/x/net/http2/h2i",
    srcs = ["golang.org/x/net/http2/h2i/h2i.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/crypto/ssh/terminal",
        "//vendor:golang.org/x/net/http2",
        "//vendor:golang.org/x/net/http2/hpack",
    ],
)

go_library(
    name = "golang.org/x/net/http2/hpack",
    srcs = [
        "golang.org/x/net/http2/hpack/encode.go",
        "golang.org/x/net/http2/hpack/hpack.go",
        "golang.org/x/net/http2/hpack/huffman.go",
        "golang.org/x/net/http2/hpack/tables.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "golang.org/x/net/idna",
    srcs = [
        "golang.org/x/net/idna/idna.go",
        "golang.org/x/net/idna/punycode.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "golang.org/x/net/internal/timeseries",
    srcs = ["golang.org/x/net/internal/timeseries/timeseries.go"],
    tags = ["automanaged"],
)

go_library(
    name = "golang.org/x/net/lex/httplex",
    srcs = ["golang.org/x/net/lex/httplex/httplex.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/net/idna"],
)

go_library(
    name = "golang.org/x/net/trace",
    srcs = [
        "golang.org/x/net/trace/events.go",
        "golang.org/x/net/trace/histogram.go",
        "golang.org/x/net/trace/trace.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/net/internal/timeseries",
    ],
)

go_library(
    name = "golang.org/x/oauth2",
    srcs = [
        "golang.org/x/oauth2/oauth2.go",
        "golang.org/x/oauth2/token.go",
        "golang.org/x/oauth2/transport.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/oauth2/internal",
    ],
)

go_library(
    name = "golang.org/x/oauth2/bitbucket",
    srcs = ["golang.org/x/oauth2/bitbucket/bitbucket.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/clientcredentials",
    srcs = ["golang.org/x/oauth2/clientcredentials/clientcredentials.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/oauth2",
        "//vendor:golang.org/x/oauth2/internal",
    ],
)

go_library(
    name = "golang.org/x/oauth2/facebook",
    srcs = ["golang.org/x/oauth2/facebook/facebook.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/fitbit",
    srcs = ["golang.org/x/oauth2/fitbit/fitbit.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/foursquare",
    srcs = ["golang.org/x/oauth2/foursquare/foursquare.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/github",
    srcs = ["golang.org/x/oauth2/github/github.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/google",
    srcs = [
        "golang.org/x/oauth2/google/appengine.go",
        "golang.org/x/oauth2/google/default.go",
        "golang.org/x/oauth2/google/google.go",
        "golang.org/x/oauth2/google/jwt.go",
        "golang.org/x/oauth2/google/sdk.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:cloud.google.com/go/compute/metadata",
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/oauth2",
        "//vendor:golang.org/x/oauth2/internal",
        "//vendor:golang.org/x/oauth2/jws",
        "//vendor:golang.org/x/oauth2/jwt",
    ],
)

go_library(
    name = "golang.org/x/oauth2/heroku",
    srcs = ["golang.org/x/oauth2/heroku/heroku.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/hipchat",
    srcs = ["golang.org/x/oauth2/hipchat/hipchat.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/oauth2",
        "//vendor:golang.org/x/oauth2/clientcredentials",
    ],
)

go_library(
    name = "golang.org/x/oauth2/internal",
    srcs = [
        "golang.org/x/oauth2/internal/oauth2.go",
        "golang.org/x/oauth2/internal/token.go",
        "golang.org/x/oauth2/internal/transport.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/net/context"],
)

go_library(
    name = "golang.org/x/oauth2/jws",
    srcs = ["golang.org/x/oauth2/jws/jws.go"],
    tags = ["automanaged"],
)

go_library(
    name = "golang.org/x/oauth2/jwt",
    srcs = ["golang.org/x/oauth2/jwt/jwt.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/oauth2",
        "//vendor:golang.org/x/oauth2/internal",
        "//vendor:golang.org/x/oauth2/jws",
    ],
)

go_library(
    name = "golang.org/x/oauth2/linkedin",
    srcs = ["golang.org/x/oauth2/linkedin/linkedin.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/mediamath",
    srcs = ["golang.org/x/oauth2/mediamath/mediamath.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/microsoft",
    srcs = ["golang.org/x/oauth2/microsoft/microsoft.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/odnoklassniki",
    srcs = ["golang.org/x/oauth2/odnoklassniki/odnoklassniki.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/paypal",
    srcs = ["golang.org/x/oauth2/paypal/paypal.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/slack",
    srcs = ["golang.org/x/oauth2/slack/slack.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/uber",
    srcs = ["golang.org/x/oauth2/uber/uber.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "golang.org/x/oauth2/vk",
    srcs = ["golang.org/x/oauth2/vk/vk.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/oauth2"],
)

go_library(
    name = "google.golang.org/api/compute/v1",
    srcs = ["google.golang.org/api/compute/v1/compute-gen.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/net/context/ctxhttp",
        "//vendor:google.golang.org/api/gensupport",
        "//vendor:google.golang.org/api/googleapi",
    ],
)

go_library(
    name = "google.golang.org/api/gensupport",
    srcs = [
        "google.golang.org/api/gensupport/backoff.go",
        "google.golang.org/api/gensupport/buffer.go",
        "google.golang.org/api/gensupport/doc.go",
        "google.golang.org/api/gensupport/json.go",
        "google.golang.org/api/gensupport/jsonfloat.go",
        "google.golang.org/api/gensupport/media.go",
        "google.golang.org/api/gensupport/params.go",
        "google.golang.org/api/gensupport/resumable.go",
        "google.golang.org/api/gensupport/retry.go",
        "google.golang.org/api/gensupport/send.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/net/context/ctxhttp",
        "//vendor:google.golang.org/api/googleapi",
    ],
)

go_library(
    name = "google.golang.org/api/googleapi",
    srcs = [
        "google.golang.org/api/googleapi/googleapi.go",
        "google.golang.org/api/googleapi/types.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor:google.golang.org/api/googleapi/internal/uritemplates"],
)

go_library(
    name = "google.golang.org/api/googleapi/internal/uritemplates",
    srcs = [
        "google.golang.org/api/googleapi/internal/uritemplates/uritemplates.go",
        "google.golang.org/api/googleapi/internal/uritemplates/utils.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/api/googleapi/transport",
    srcs = ["google.golang.org/api/googleapi/transport/apikey.go"],
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/appengine",
    srcs = [
        "google.golang.org/appengine/appengine.go",
        "google.golang.org/appengine/appengine_vm.go",
        "google.golang.org/appengine/errors.go",
        "google.golang.org/appengine/identity.go",
        "google.golang.org/appengine/namespace.go",
        "google.golang.org/appengine/timeout.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/app_identity",
        "//vendor:google.golang.org/appengine/internal/modules",
    ],
)

go_library(
    name = "google.golang.org/appengine/aetest",
    srcs = [
        "google.golang.org/appengine/aetest/doc.go",
        "google.golang.org/appengine/aetest/instance.go",
        "google.golang.org/appengine/aetest/instance_vm.go",
        "google.golang.org/appengine/aetest/user.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/user",
    ],
)

go_library(
    name = "google.golang.org/appengine/blobstore",
    srcs = [
        "google.golang.org/appengine/blobstore/blobstore.go",
        "google.golang.org/appengine/blobstore/read.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/datastore",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/base",
        "//vendor:google.golang.org/appengine/internal/blobstore",
    ],
)

go_library(
    name = "google.golang.org/appengine/capability",
    srcs = ["google.golang.org/appengine/capability/capability.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/capability",
        "//vendor:google.golang.org/appengine/log",
    ],
)

go_library(
    name = "google.golang.org/appengine/channel",
    srcs = ["google.golang.org/appengine/channel/channel.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/base",
        "//vendor:google.golang.org/appengine/internal/channel",
    ],
)

go_library(
    name = "google.golang.org/appengine/cloudsql",
    srcs = [
        "google.golang.org/appengine/cloudsql/cloudsql.go",
        "google.golang.org/appengine/cloudsql/cloudsql_vm.go",
    ],
    tags = ["automanaged"],
)

go_binary(
    name = "google.golang.org/appengine/cmd/aebundler_bin",
    library = ":google.golang.org/appengine/cmd/aebundler",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/appengine/cmd/aebundler",
    srcs = ["google.golang.org/appengine/cmd/aebundler/aebundler.go"],
    tags = ["automanaged"],
)

go_binary(
    name = "google.golang.org/appengine/cmd/aedeploy_bin",
    library = ":google.golang.org/appengine/cmd/aedeploy",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/appengine/cmd/aedeploy",
    srcs = ["google.golang.org/appengine/cmd/aedeploy/aedeploy.go"],
    tags = ["automanaged"],
)

go_binary(
    name = "google.golang.org/appengine/cmd/aefix_bin",
    library = ":google.golang.org/appengine/cmd/aefix",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/appengine/cmd/aefix",
    srcs = [
        "google.golang.org/appengine/cmd/aefix/ae.go",
        "google.golang.org/appengine/cmd/aefix/fix.go",
        "google.golang.org/appengine/cmd/aefix/main.go",
        "google.golang.org/appengine/cmd/aefix/typecheck.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/appengine/datastore",
    srcs = [
        "google.golang.org/appengine/datastore/datastore.go",
        "google.golang.org/appengine/datastore/doc.go",
        "google.golang.org/appengine/datastore/key.go",
        "google.golang.org/appengine/datastore/load.go",
        "google.golang.org/appengine/datastore/metadata.go",
        "google.golang.org/appengine/datastore/prop.go",
        "google.golang.org/appengine/datastore/query.go",
        "google.golang.org/appengine/datastore/save.go",
        "google.golang.org/appengine/datastore/transaction.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/datastore",
    ],
)

go_library(
    name = "google.golang.org/appengine/delay",
    srcs = ["google.golang.org/appengine/delay/delay.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/log",
        "//vendor:google.golang.org/appengine/taskqueue",
    ],
)

go_binary(
    name = "google.golang.org/appengine/demos/guestbook_bin",
    library = ":google.golang.org/appengine/demos/guestbook",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/appengine/demos/guestbook",
    srcs = ["google.golang.org/appengine/demos/guestbook/guestbook.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/datastore",
        "//vendor:google.golang.org/appengine/log",
        "//vendor:google.golang.org/appengine/user",
    ],
)

go_binary(
    name = "google.golang.org/appengine/demos/helloworld_bin",
    library = ":google.golang.org/appengine/demos/helloworld",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/appengine/demos/helloworld",
    srcs = ["google.golang.org/appengine/demos/helloworld/helloworld.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/log",
    ],
)

go_library(
    name = "google.golang.org/appengine/file",
    srcs = ["google.golang.org/appengine/file/file.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/app_identity",
    ],
)

go_library(
    name = "google.golang.org/appengine/image",
    srcs = ["google.golang.org/appengine/image/image.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/image",
    ],
)

go_library(
    name = "google.golang.org/appengine/internal",
    srcs = [
        "google.golang.org/appengine/internal/api.go",
        "google.golang.org/appengine/internal/api_common.go",
        "google.golang.org/appengine/internal/app_id.go",
        "google.golang.org/appengine/internal/identity.go",
        "google.golang.org/appengine/internal/identity_vm.go",
        "google.golang.org/appengine/internal/internal.go",
        "google.golang.org/appengine/internal/main_vm.go",
        "google.golang.org/appengine/internal/metadata.go",
        "google.golang.org/appengine/internal/net.go",
        "google.golang.org/appengine/internal/transaction.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine/internal/base",
        "//vendor:google.golang.org/appengine/internal/datastore",
        "//vendor:google.golang.org/appengine/internal/log",
        "//vendor:google.golang.org/appengine/internal/remote_api",
    ],
)

go_library(
    name = "google.golang.org/appengine/internal/aetesting",
    srcs = ["google.golang.org/appengine/internal/aetesting/fake.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine/internal",
    ],
)

go_library(
    name = "google.golang.org/appengine/internal/app_identity",
    srcs = ["google.golang.org/appengine/internal/app_identity/app_identity_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/base",
    srcs = ["google.golang.org/appengine/internal/base/api_base.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/blobstore",
    srcs = ["google.golang.org/appengine/internal/blobstore/blobstore_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/capability",
    srcs = ["google.golang.org/appengine/internal/capability/capability_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/channel",
    srcs = ["google.golang.org/appengine/internal/channel/channel_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/datastore",
    srcs = ["google.golang.org/appengine/internal/datastore/datastore_v3.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/image",
    srcs = ["google.golang.org/appengine/internal/image/images_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/log",
    srcs = ["google.golang.org/appengine/internal/log/log_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/mail",
    srcs = ["google.golang.org/appengine/internal/mail/mail_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/memcache",
    srcs = ["google.golang.org/appengine/internal/memcache/memcache_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/modules",
    srcs = ["google.golang.org/appengine/internal/modules/modules_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/remote_api",
    srcs = ["google.golang.org/appengine/internal/remote_api/remote_api.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/search",
    srcs = ["google.golang.org/appengine/internal/search/search.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/socket",
    srcs = ["google.golang.org/appengine/internal/socket/socket_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/system",
    srcs = ["google.golang.org/appengine/internal/system/system_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/taskqueue",
    srcs = ["google.golang.org/appengine/internal/taskqueue/taskqueue_service.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:google.golang.org/appengine/internal/datastore",
    ],
)

go_library(
    name = "google.golang.org/appengine/internal/urlfetch",
    srcs = ["google.golang.org/appengine/internal/urlfetch/urlfetch_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/user",
    srcs = ["google.golang.org/appengine/internal/user/user_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/internal/xmpp",
    srcs = ["google.golang.org/appengine/internal/xmpp/xmpp_service.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/appengine/log",
    srcs = [
        "google.golang.org/appengine/log/api.go",
        "google.golang.org/appengine/log/log.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/log",
    ],
)

go_library(
    name = "google.golang.org/appengine/mail",
    srcs = ["google.golang.org/appengine/mail/mail.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/base",
        "//vendor:google.golang.org/appengine/internal/mail",
    ],
)

go_library(
    name = "google.golang.org/appengine/memcache",
    srcs = ["google.golang.org/appengine/memcache/memcache.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/memcache",
    ],
)

go_library(
    name = "google.golang.org/appengine/module",
    srcs = ["google.golang.org/appengine/module/module.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/modules",
    ],
)

go_library(
    name = "google.golang.org/appengine/remote_api",
    srcs = [
        "google.golang.org/appengine/remote_api/client.go",
        "google.golang.org/appengine/remote_api/remote_api.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/remote_api",
        "//vendor:google.golang.org/appengine/log",
        "//vendor:google.golang.org/appengine/user",
    ],
)

go_library(
    name = "google.golang.org/appengine/runtime",
    srcs = ["google.golang.org/appengine/runtime/runtime.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/system",
    ],
)

go_library(
    name = "google.golang.org/appengine/search",
    srcs = [
        "google.golang.org/appengine/search/doc.go",
        "google.golang.org/appengine/search/field.go",
        "google.golang.org/appengine/search/search.go",
        "google.golang.org/appengine/search/struct.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/search",
    ],
)

go_library(
    name = "google.golang.org/appengine/socket",
    srcs = [
        "google.golang.org/appengine/socket/doc.go",
        "google.golang.org/appengine/socket/socket_vm.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/net/context"],
)

go_library(
    name = "google.golang.org/appengine/taskqueue",
    srcs = ["google.golang.org/appengine/taskqueue/taskqueue.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/datastore",
        "//vendor:google.golang.org/appengine/internal/taskqueue",
    ],
)

go_library(
    name = "google.golang.org/appengine/urlfetch",
    srcs = ["google.golang.org/appengine/urlfetch/urlfetch.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/urlfetch",
    ],
)

go_library(
    name = "google.golang.org/appengine/user",
    srcs = [
        "google.golang.org/appengine/user/oauth.go",
        "google.golang.org/appengine/user/user.go",
        "google.golang.org/appengine/user/user_vm.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/user",
    ],
)

go_library(
    name = "google.golang.org/appengine/xmpp",
    srcs = ["google.golang.org/appengine/xmpp/xmpp.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/appengine",
        "//vendor:google.golang.org/appengine/internal",
        "//vendor:google.golang.org/appengine/internal/xmpp",
    ],
)

go_library(
    name = "google.golang.org/grpc",
    srcs = [
        "google.golang.org/grpc/backoff.go",
        "google.golang.org/grpc/balancer.go",
        "google.golang.org/grpc/call.go",
        "google.golang.org/grpc/clientconn.go",
        "google.golang.org/grpc/doc.go",
        "google.golang.org/grpc/interceptor.go",
        "google.golang.org/grpc/rpc_util.go",
        "google.golang.org/grpc/server.go",
        "google.golang.org/grpc/stream.go",
        "google.golang.org/grpc/trace.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/net/http2",
        "//vendor:golang.org/x/net/trace",
        "//vendor:google.golang.org/grpc/codes",
        "//vendor:google.golang.org/grpc/credentials",
        "//vendor:google.golang.org/grpc/grpclog",
        "//vendor:google.golang.org/grpc/internal",
        "//vendor:google.golang.org/grpc/metadata",
        "//vendor:google.golang.org/grpc/naming",
        "//vendor:google.golang.org/grpc/stats",
        "//vendor:google.golang.org/grpc/tap",
        "//vendor:google.golang.org/grpc/transport",
    ],
)

go_library(
    name = "google.golang.org/grpc/benchmark",
    srcs = ["google.golang.org/grpc/benchmark/benchmark.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/benchmark/grpc_testing",
        "//vendor:google.golang.org/grpc/grpclog",
    ],
)

go_binary(
    name = "google.golang.org/grpc/benchmark/client_bin",
    library = ":google.golang.org/grpc/benchmark/client",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/benchmark/client",
    srcs = ["google.golang.org/grpc/benchmark/client/main.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/benchmark",
        "//vendor:google.golang.org/grpc/benchmark/grpc_testing",
        "//vendor:google.golang.org/grpc/benchmark/stats",
        "//vendor:google.golang.org/grpc/grpclog",
    ],
)

go_library(
    name = "google.golang.org/grpc/benchmark/grpc_testing",
    srcs = [
        "google.golang.org/grpc/benchmark/grpc_testing/control.pb.go",
        "google.golang.org/grpc/benchmark/grpc_testing/messages.pb.go",
        "google.golang.org/grpc/benchmark/grpc_testing/payloads.pb.go",
        "google.golang.org/grpc/benchmark/grpc_testing/services.pb.go",
        "google.golang.org/grpc/benchmark/grpc_testing/stats.pb.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_binary(
    name = "google.golang.org/grpc/benchmark/server_bin",
    library = ":google.golang.org/grpc/benchmark/server",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/benchmark/server",
    srcs = ["google.golang.org/grpc/benchmark/server/main.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:google.golang.org/grpc/benchmark",
        "//vendor:google.golang.org/grpc/grpclog",
    ],
)

go_library(
    name = "google.golang.org/grpc/benchmark/stats",
    srcs = [
        "google.golang.org/grpc/benchmark/stats/histogram.go",
        "google.golang.org/grpc/benchmark/stats/stats.go",
        "google.golang.org/grpc/benchmark/stats/util.go",
    ],
    tags = ["automanaged"],
)

go_binary(
    name = "google.golang.org/grpc/benchmark/worker_bin",
    library = ":google.golang.org/grpc/benchmark/worker",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/benchmark/worker",
    srcs = [
        "google.golang.org/grpc/benchmark/worker/benchmark_client.go",
        "google.golang.org/grpc/benchmark/worker/benchmark_server.go",
        "google.golang.org/grpc/benchmark/worker/main.go",
        "google.golang.org/grpc/benchmark/worker/util.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/benchmark",
        "//vendor:google.golang.org/grpc/benchmark/grpc_testing",
        "//vendor:google.golang.org/grpc/benchmark/stats",
        "//vendor:google.golang.org/grpc/codes",
        "//vendor:google.golang.org/grpc/credentials",
        "//vendor:google.golang.org/grpc/grpclog",
    ],
)

go_library(
    name = "google.golang.org/grpc/codes",
    srcs = [
        "google.golang.org/grpc/codes/code_string.go",
        "google.golang.org/grpc/codes/codes.go",
    ],
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/credentials",
    srcs = [
        "google.golang.org/grpc/credentials/credentials.go",
        "google.golang.org/grpc/credentials/credentials_util_go17.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/net/context"],
)

go_library(
    name = "google.golang.org/grpc/credentials/oauth",
    srcs = ["google.golang.org/grpc/credentials/oauth/oauth.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/oauth2",
        "//vendor:golang.org/x/oauth2/google",
        "//vendor:golang.org/x/oauth2/jwt",
        "//vendor:google.golang.org/grpc/credentials",
    ],
)

go_binary(
    name = "google.golang.org/grpc/examples/helloworld/greeter_client_bin",
    library = ":google.golang.org/grpc/examples/helloworld/greeter_client",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/examples/helloworld/greeter_client",
    srcs = ["google.golang.org/grpc/examples/helloworld/greeter_client/main.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/examples/helloworld/helloworld",
    ],
)

go_binary(
    name = "google.golang.org/grpc/examples/helloworld/greeter_server_bin",
    library = ":google.golang.org/grpc/examples/helloworld/greeter_server",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/examples/helloworld/greeter_server",
    srcs = ["google.golang.org/grpc/examples/helloworld/greeter_server/main.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/examples/helloworld/helloworld",
        "//vendor:google.golang.org/grpc/reflection",
    ],
)

go_library(
    name = "google.golang.org/grpc/examples/helloworld/helloworld",
    srcs = ["google.golang.org/grpc/examples/helloworld/helloworld/helloworld.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_binary(
    name = "google.golang.org/grpc/examples/route_guide/client_bin",
    library = ":google.golang.org/grpc/examples/route_guide/client",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/examples/route_guide/client",
    srcs = ["google.golang.org/grpc/examples/route_guide/client/client.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/credentials",
        "//vendor:google.golang.org/grpc/examples/route_guide/routeguide",
        "//vendor:google.golang.org/grpc/grpclog",
    ],
)

go_library(
    name = "google.golang.org/grpc/examples/route_guide/routeguide",
    srcs = ["google.golang.org/grpc/examples/route_guide/routeguide/route_guide.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_binary(
    name = "google.golang.org/grpc/examples/route_guide/server_bin",
    library = ":google.golang.org/grpc/examples/route_guide/server",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/examples/route_guide/server",
    srcs = ["google.golang.org/grpc/examples/route_guide/server/server.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/credentials",
        "//vendor:google.golang.org/grpc/examples/route_guide/routeguide",
        "//vendor:google.golang.org/grpc/grpclog",
    ],
)

go_library(
    name = "google.golang.org/grpc/grpclb",
    srcs = ["google.golang.org/grpc/grpclb/grpclb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/codes",
        "//vendor:google.golang.org/grpc/grpclb/grpc_lb_v1",
        "//vendor:google.golang.org/grpc/grpclog",
        "//vendor:google.golang.org/grpc/metadata",
        "//vendor:google.golang.org/grpc/naming",
    ],
)

go_library(
    name = "google.golang.org/grpc/grpclb/grpc_lb_v1",
    srcs = ["google.golang.org/grpc/grpclb/grpc_lb_v1/grpclb.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_library(
    name = "google.golang.org/grpc/grpclog",
    srcs = ["google.golang.org/grpc/grpclog/logger.go"],
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/grpclog/glogger",
    srcs = ["google.golang.org/grpc/grpclog/glogger/glogger.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/glog",
        "//vendor:google.golang.org/grpc/grpclog",
    ],
)

go_library(
    name = "google.golang.org/grpc/health",
    srcs = ["google.golang.org/grpc/health/health.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/codes",
        "//vendor:google.golang.org/grpc/health/grpc_health_v1",
    ],
)

go_library(
    name = "google.golang.org/grpc/health/grpc_health_v1",
    srcs = ["google.golang.org/grpc/health/grpc_health_v1/health.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_library(
    name = "google.golang.org/grpc/internal",
    srcs = ["google.golang.org/grpc/internal/internal.go"],
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/interop",
    srcs = ["google.golang.org/grpc/interop/test_utils.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/oauth2",
        "//vendor:golang.org/x/oauth2/google",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/codes",
        "//vendor:google.golang.org/grpc/grpclog",
        "//vendor:google.golang.org/grpc/interop/grpc_testing",
        "//vendor:google.golang.org/grpc/metadata",
    ],
)

go_binary(
    name = "google.golang.org/grpc/interop/client_bin",
    library = ":google.golang.org/grpc/interop/client",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/interop/client",
    srcs = ["google.golang.org/grpc/interop/client/client.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/credentials",
        "//vendor:google.golang.org/grpc/credentials/oauth",
        "//vendor:google.golang.org/grpc/grpclog",
        "//vendor:google.golang.org/grpc/interop",
        "//vendor:google.golang.org/grpc/interop/grpc_testing",
    ],
)

go_library(
    name = "google.golang.org/grpc/interop/grpc_testing",
    srcs = ["google.golang.org/grpc/interop/grpc_testing/test.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_binary(
    name = "google.golang.org/grpc/interop/server_bin",
    library = ":google.golang.org/grpc/interop/server",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/interop/server",
    srcs = ["google.golang.org/grpc/interop/server/server.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/credentials",
        "//vendor:google.golang.org/grpc/grpclog",
        "//vendor:google.golang.org/grpc/interop",
        "//vendor:google.golang.org/grpc/interop/grpc_testing",
    ],
)

go_library(
    name = "google.golang.org/grpc/metadata",
    srcs = ["google.golang.org/grpc/metadata/metadata.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/net/context"],
)

go_library(
    name = "google.golang.org/grpc/naming",
    srcs = ["google.golang.org/grpc/naming/naming.go"],
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/peer",
    srcs = ["google.golang.org/grpc/peer/peer.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc/credentials",
    ],
)

go_library(
    name = "google.golang.org/grpc/reflection",
    srcs = ["google.golang.org/grpc/reflection/serverreflection.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:github.com/golang/protobuf/protoc-gen-go/descriptor",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/codes",
        "//vendor:google.golang.org/grpc/reflection/grpc_reflection_v1alpha",
    ],
)

go_library(
    name = "google.golang.org/grpc/reflection/grpc_reflection_v1alpha",
    srcs = ["google.golang.org/grpc/reflection/grpc_reflection_v1alpha/reflection.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_library(
    name = "google.golang.org/grpc/reflection/grpc_testing",
    srcs = [
        "google.golang.org/grpc/reflection/grpc_testing/proto2.pb.go",
        "google.golang.org/grpc/reflection/grpc_testing/proto2_ext.pb.go",
        "google.golang.org/grpc/reflection/grpc_testing/test.pb.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_library(
    name = "google.golang.org/grpc/stats",
    srcs = [
        "google.golang.org/grpc/stats/handlers.go",
        "google.golang.org/grpc/stats/stats.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/net/context"],
)

go_library(
    name = "google.golang.org/grpc/stats/grpc_testing",
    srcs = ["google.golang.org/grpc/stats/grpc_testing/test.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_binary(
    name = "google.golang.org/grpc/stress/client_bin",
    library = ":google.golang.org/grpc/stress/client",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/stress/client",
    srcs = ["google.golang.org/grpc/stress/client/main.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/codes",
        "//vendor:google.golang.org/grpc/credentials",
        "//vendor:google.golang.org/grpc/grpclog",
        "//vendor:google.golang.org/grpc/interop",
        "//vendor:google.golang.org/grpc/interop/grpc_testing",
        "//vendor:google.golang.org/grpc/stress/grpc_testing",
    ],
)

go_library(
    name = "google.golang.org/grpc/stress/grpc_testing",
    srcs = ["google.golang.org/grpc/stress/grpc_testing/metrics.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_binary(
    name = "google.golang.org/grpc/stress/metrics_client_bin",
    library = ":google.golang.org/grpc/stress/metrics_client",
    tags = ["automanaged"],
)

go_library(
    name = "google.golang.org/grpc/stress/metrics_client",
    srcs = ["google.golang.org/grpc/stress/metrics_client/main.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
        "//vendor:google.golang.org/grpc/grpclog",
        "//vendor:google.golang.org/grpc/stress/grpc_testing",
    ],
)

go_library(
    name = "google.golang.org/grpc/tap",
    srcs = ["google.golang.org/grpc/tap/tap.go"],
    tags = ["automanaged"],
    deps = ["//vendor:golang.org/x/net/context"],
)

go_library(
    name = "google.golang.org/grpc/test/codec_perf",
    srcs = ["google.golang.org/grpc/test/codec_perf/perf.pb.go"],
    tags = ["automanaged"],
    deps = ["//vendor:github.com/golang/protobuf/proto"],
)

go_library(
    name = "google.golang.org/grpc/test/grpc_testing",
    srcs = ["google.golang.org/grpc/test/grpc_testing/test.pb.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/golang/protobuf/proto",
        "//vendor:golang.org/x/net/context",
        "//vendor:google.golang.org/grpc",
    ],
)

go_library(
    name = "google.golang.org/grpc/transport",
    srcs = [
        "google.golang.org/grpc/transport/control.go",
        "google.golang.org/grpc/transport/go17.go",
        "google.golang.org/grpc/transport/handler_server.go",
        "google.golang.org/grpc/transport/http2_client.go",
        "google.golang.org/grpc/transport/http2_server.go",
        "google.golang.org/grpc/transport/http_util.go",
        "google.golang.org/grpc/transport/transport.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:golang.org/x/net/context",
        "//vendor:golang.org/x/net/http2",
        "//vendor:golang.org/x/net/http2/hpack",
        "//vendor:google.golang.org/grpc/codes",
        "//vendor:google.golang.org/grpc/credentials",
        "//vendor:google.golang.org/grpc/grpclog",
        "//vendor:google.golang.org/grpc/metadata",
        "//vendor:google.golang.org/grpc/peer",
        "//vendor:google.golang.org/grpc/stats",
        "//vendor:google.golang.org/grpc/tap",
    ],
)
