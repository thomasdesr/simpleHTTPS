load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library", "go_prefix")

go_prefix("github.com/thomaso-mirodin/simpleHTTPS")

go_binary(
    name = "simpleHTTPS",
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "http.go",
        "main.go",
        "tls.go",
        "tls_fingerprints.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor:github.com/Sirupsen/logrus",
        "//vendor:github.com/jessevdk/go-flags",
    ],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"], exclude=["bazel-*/**", ".git/**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [
        ":package-srcs",
        "//vendor:all-srcs",
    ],
    tags = ["automanaged"],
)
