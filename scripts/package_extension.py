#!/usr/bin/env python3
"""
Packages ide-extension directory into a compliant VS Code / Antigravity .vsix package.
"""

import os
import zipfile
import json

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ide-extension"))
VSIX_OUT = os.path.join(BASE_DIR, "sentinel-appsec-ide-1.0.0.vsix")

CONTENT_TYPES_XML = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="vsixmanifest" ContentType="text/xml"/>
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
  <Default Extension="md" ContentType="text/markdown"/>
  <Default Extension="svg" ContentType="image/svg+xml"/>
</Types>
"""

VSIX_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="sentinel-appsec-ide" Version="1.0.0" Publisher="sentinel-security"/>
    <DisplayName>Sentinel AppSec &amp; Custom Rule Engine</DisplayName>
    <Description xml:space="preserve">Real-time AST security scanning, vulnerability diagnostics, hover tooltips, and project custom rules reflection (.sentinel/rules.yaml).</Description>
    <Tags>security,sast,iac,cisa-kev,secrets,owasp,misra,iso27001,custom-rules,cloud</Tags>
    <Categories>Linters,Programming Languages,Other</Categories>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true"/>
  </Assets>
</PackageManifest>
"""


def build_vsix():
    print(f"📦 Packaging Sentinel IDE extension from {BASE_DIR}...")
    with zipfile.ZipFile(VSIX_OUT, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("extension.vsixmanifest", VSIX_MANIFEST.strip())
        zf.writestr("[Content_Types].xml", CONTENT_TYPES_XML.strip())

        # Include extension files
        for root, dirs, files in os.walk(BASE_DIR):
            for file in files:
                if file.endswith(".vsix"):
                    continue
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, BASE_DIR)
                arc_path = os.path.join("extension", rel_path)
                zf.write(abs_path, arc_path)
                print(f"  + {arc_path}")

    print(f"✅ Created {VSIX_OUT} ({os.path.getsize(VSIX_OUT)} bytes)")


if __name__ == "__main__":
    build_vsix()
