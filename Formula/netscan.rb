class Netscan < Formula
  desc "Network scanner and analyser with a command line tool and a desktop application"
  homepage "https://github.com/sssst9s/netscan"
  url "https://github.com/sssst9s/netscan/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  head "https://github.com/sssst9s/netscan.git", branch: "main"

  depends_on "rust" => :build

  on_linux do
    depends_on "pkg-config" => :build
    depends_on "libx11"
    depends_on "libxcursor"
    depends_on "libxi"
    depends_on "libxkbcommon"
    depends_on "libxrandr"
    depends_on "mesa"
    depends_on "wayland"
  end

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/netscan-cli")
    system "cargo", "install", *std_cargo_args(path: "crates/netscan-gui")
  end

  def caveats
    <<~EOS
      Scan only networks you own or have permission to test.

      Half open SYN scanning needs raw sockets, which are behind an optional
      build feature and need elevated privileges. Build from source with
      --features raw if you need it; see INSTALL.md.
    EOS
  end

  test do
    assert_match "netscan", shell_output("#{bin}/netscan --version")
    assert_match "quick", shell_output("#{bin}/netscan --list-profiles")
    output = shell_output("#{bin}/netscan 127.0.0.1 -p 1 --no-discovery --json")
    assert_match "\"schema_version\"", output
  end
end
