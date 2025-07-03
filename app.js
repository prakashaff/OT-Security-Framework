// OT Security Framework data
const frameworkData = {
  "name": "OT Security Framework",
  "children": [
    {
      "name": "Asset Discovery & Inventory",
      "children": [
        {
          "name": "Network Scanning Tools",
          "children": [
            {
              "name": "Nmap with ICS Scripts (T)",
              "url": "https://nmap.org/",
              "type": "link"
            },
            {
              "name": "Shodan for Industrial Devices (R)",
              "url": "https://www.shodan.io/",
              "type": "link"
            },
            {
              "name": "ZoomEye (R)",
              "url": "https://www.zoomeye.org/",
              "type": "link"
            },
            {
              "name": "Censys (R)",
              "url": "https://censys.io/",
              "type": "link"
            }
          ]
        },
        {
          "name": "Device Identification",
          "children": [
            {
              "name": "Industrial Defender ASM (R)",
              "url": "https://www.industrialdefender.com/",
              "type": "link"
            },
            {
              "name": "Claroty xDome (R)",
              "url": "https://claroty.com/",
              "type": "link"
            },
            {
              "name": "Dragos Platform (R)",
              "url": "https://www.dragos.com/",
              "type": "link"
            },
            {
              "name": "Nozomi Networks (R)",
              "url": "https://www.nozominetworks.com/",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "Network Security",
      "children": [
        {
          "name": "Network Monitoring",
          "children": [
            {
              "name": "Security Onion (T)",
              "url": "https://securityonionsolutions.com/",
              "type": "link"
            },
            {
              "name": "Wireshark (T)",
              "url": "https://www.wireshark.org/",
              "type": "link"
            },
            {
              "name": "Zeek with OT plugins (T)",
              "url": "https://zeek.org/",
              "type": "link"
            },
            {
              "name": "NetworkMiner (T)",
              "url": "https://www.netresec.com/?page=NetworkMiner",
              "type": "link"
            }
          ]
        },
        {
          "name": "Intrusion Detection",
          "children": [
            {
              "name": "Snort with ICS rules (T)",
              "url": "https://www.snort.org/",
              "type": "link"
            },
            {
              "name": "Suricata (T)",
              "url": "https://suricata-ids.org/",
              "type": "link"
            },
            {
              "name": "OSSEC (T)",
              "url": "https://www.ossec.net/",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "Protocol Security",
      "children": [
        {
          "name": "Modbus Security",
          "children": [
            {
              "name": "ModScan (T)",
              "url": "https://www.modscan.com/",
              "type": "link"
            },
            {
              "name": "Modbus protocol analyzers",
              "url": "https://github.com/enddo/smod",
              "type": "link"
            }
          ]
        },
        {
          "name": "DNP3 Analysis",
          "children": [
            {
              "name": "DNP3 protocol tools",
              "url": "https://www.triangle-microworks.com/",
              "type": "link"
            }
          ]
        },
        {
          "name": "OPC UA Security",
          "children": [
            {
              "name": "OPC UA security scanners",
              "url": "https://opcfoundation.org/developer-tools/",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "Device Security",
      "children": [
        {
          "name": "PLC Security",
          "children": [
            {
              "name": "PLC-VBS Scanner (T)",
              "url": "https://github.com/SCADACS/PLC-VBS",
              "type": "link"
            },
            {
              "name": "ICSpector (T)",
              "url": "https://github.com/shodan-labs/icspector",
              "type": "link"
            },
            {
              "name": "PLCScan (T)",
              "url": "https://github.com/meeas/plcscan",
              "type": "link"
            }
          ]
        },
        {
          "name": "SCADA Security",
          "children": [
            {
              "name": "VTScada Security",
              "url": "https://www.vtscada.com/",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "Vulnerability Management",
      "children": [
        {
          "name": "Vulnerability Scanners",
          "children": [
            {
              "name": "OpenVAS with ICS plugins (T)",
              "url": "https://www.openvas.org/",
              "type": "link"
            },
            {
              "name": "Nessus Industrial (R)",
              "url": "https://www.tenable.com/products/nessus",
              "type": "link"
            },
            {
              "name": "Rapid7 InsightVM (R)",
              "url": "https://www.rapid7.com/products/insightvm/",
              "type": "link"
            },
            {
              "name": "Qualys VMDR (R)",
              "url": "https://www.qualys.com/apps/vulnerability-management/",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "Penetration Testing",
      "children": [
        {
          "name": "OT Pentesting Tools",
          "children": [
            {
              "name": "Metasploit with ICS modules (T)",
              "url": "https://www.metasploit.com/",
              "type": "link"
            },
            {
              "name": "ICS Exploit Framework (T)",
              "url": "https://github.com/dark-lbp/isf",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "Honeypots & Deception",
      "children": [
        {
          "name": "ICS Honeypots",
          "children": [
            {
              "name": "Conpot (T)",
              "url": "https://conpot.org/",
              "type": "link"
            },
            {
              "name": "GasPot (T)",
              "url": "https://github.com/sjhilt/GasPot",
              "type": "link"
            },
            {
              "name": "GridPot (T)",
              "url": "https://github.com/sk4ld/gridpot",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "Threat Intelligence",
      "children": [
        {
          "name": "Threat Feeds",
          "children": [
            {
              "name": "ICS-CERT Advisories",
              "url": "https://www.cisa.gov/uscert/ics/advisories",
              "type": "link"
            },
            {
              "name": "MITRE ATT&CK for ICS",
              "url": "https://attack.mitre.org/matrices/ics/",
              "type": "link"
            },
            {
              "name": "Dragos Threat Intelligence (R)",
              "url": "https://www.dragos.com/threat-intelligence/",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "Compliance & Standards",
      "children": [
        {
          "name": "IEC 62443",
          "children": [
            {
              "name": "Standard documentation",
              "url": "https://www.iec.ch/dyn/www/f?p=103:7:0::::FSP_ORG_ID:1316",
              "type": "link"
            },
            {
              "name": "Implementation guides",
              "url": "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
              "type": "link"
            }
          ]
        },
        {
          "name": "NIST Cybersecurity Framework",
          "children": [
            {
              "name": "NIST SP 800-82 r3",
              "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "Compliance Templates & Reports",
      "children": [
        {
          "name": "Assessment Templates",
          "children": [
            {
              "name": "IEC 62443-3-3 Self-Assessment",
              "url": "https://www.isa.org/getmedia/b5b1f2c7-3f18-4b7d-9e52-a1d7b9b7f8a9/ISA-IEC-62443-3-3-Self-Assessment.pdf",
              "type": "link"
            },
            {
              "name": "NIST OT Security Templates",
              "url": "https://www.nist.gov/cyberframework/manufacturing",
              "type": "link"
            }
          ]
        },
        {
          "name": "Audit Checklists",
          "children": [
            {
              "name": "OT Vulnerability Assessment Report",
              "url": "https://www.sans.org/reading-room/whitepapers/ICS/paper/33343",
              "type": "link"
            },
            {
              "name": "ICS Security Audit Checklist",
              "url": "https://www.sans.org/reading-room/whitepapers/ICS/paper/36007",
              "type": "link"
            }
          ]
        }
      ]
    },
    {
      "name": "OT Security Queries",
      "children": [
        {
          "name": "Shodan Queries",
          "children": [
            {
              "name": "Modbus devices: port:502",
              "url": "https://www.shodan.io/search?query=port%3A502",
              "type": "link"
            },
            {
              "name": "BACnet systems: port:47808",
              "url": "https://www.shodan.io/search?query=port%3A47808",
              "type": "link"
            },
            {
              "name": "DNP3 protocol: port:20000",
              "url": "https://www.shodan.io/search?query=port%3A20000",
              "type": "link"
            },
            {
              "name": "OPC UA servers: port:4840",
              "url": "https://www.shodan.io/search?query=port%3A4840",
              "type": "link"
            },
            {
              "name": "EtherNet/IP: port:44818",
              "url": "https://www.shodan.io/search?query=port%3A44818",
              "type": "link"
            },
            {
              "name": "All ICS devices: tag:ics",
              "url": "https://www.shodan.io/search?query=tag%3Aics",
              "type": "link"
            },
            {
              "name": "Siemens devices: product:\"Siemens\"",
              "url": "https://www.shodan.io/search?query=product%3A%22Siemens%22",
              "type": "link"
            }
          ]
        },
        {
          "name": "ZoomEye Queries",
          "children": [
            {
              "name": "PLC devices: device:\"plc\"",
              "url": "https://www.zoomeye.org/searchResult?q=device%3A%22plc%22",
              "type": "link"
            },
            {
              "name": "DNP3 endpoints: service:\"dnp3\"",
              "url": "https://www.zoomeye.org/searchResult?q=service%3A%22dnp3%22",
              "type": "link"
            }
          ]
        }
      ]
    }
  ]
};

class OTSecurityFramework {
    constructor() {
        this.svg = null;
        this.g = null;
        this.tree = null;
        this.root = null;
        this.duration = 750;
        this.nodeId = 0;
        this.width = 0;
        this.height = 0;
        
        this.init();
    }
    
    init() {
        this.initTheme();
        this.initTree();
        window.addEventListener('resize', () => this.handleResize());
    }
    
    initTheme() {
        const themeToggle = document.getElementById('theme-toggle');
        const savedTheme = 'light'; // Default to light theme, no localStorage
        
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        themeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', newTheme);
        });
    }
    
    initTree() {
        const container = document.querySelector('.tree-container');
        this.width = container.clientWidth;
        this.height = container.clientHeight;
        
        this.svg = d3.select("#tree-svg")
            .attr("width", this.width)
            .attr("height", this.height);
        
        this.g = this.svg.append("g");
        
        // Improved zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.2, 3])
            .filter((event) => {
                // Only allow zoom on wheel events, not on drag
                return event.type === 'wheel';
            })
            .on("zoom", (event) => {
                this.g.attr("transform", event.transform);
            });
        
        this.svg.call(zoom);
        
        this.tree = d3.tree()
            .size([this.height - 40, this.width - 200])
            .separation((a, b) => (a.parent === b.parent ? 1 : 2) / a.depth);
        
        this.root = d3.hierarchy(frameworkData, d => d.children);
        this.root.x0 = this.height / 2;
        this.root.y0 = 0;
        
        this.root.children.forEach(d => this.collapse(d));
        
        this.update(this.root);
        this.centerTree();
    }
    
    collapse(d) {
        if (d.children) {
            d._children = d.children;
            d._children.forEach(child => this.collapse(child));
            d.children = null;
        }
    }
    
    centerTree() {
        const bounds = this.g.node().getBBox();
        const fullWidth = this.width;
        const fullHeight = this.height;
        const width = bounds.width;
        const height = bounds.height;
        const midX = bounds.x + width / 2;
        const midY = bounds.y + height / 2;
        
        if (width === 0 || height === 0) return;
        
        const scale = Math.min(fullWidth / width, fullHeight / height) * 0.8;
        const translate = [fullWidth / 2 - scale * midX, fullHeight / 2 - scale * midY];
        
        this.svg.transition()
            .duration(this.duration)
            .call(
                d3.zoom().transform,
                d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
            );
    }
    
    update(source) {
        const treeData = this.tree(this.root);
        const nodes = treeData.descendants();
        const links = treeData.descendants().slice(1);
        
        nodes.forEach(d => {
            d.y = d.depth * 180;
        });
        
        const node = this.g.selectAll('g.node')
            .data(nodes, d => d.id || (d.id = ++this.nodeId));
        
        const nodeEnter = node.enter().append('g')
            .attr('class', d => d.data.url ? 'node link-node' : 'node')
            .attr('transform', d => `translate(${source.y0},${source.x0})`)
            .on('click', (event, d) => {
                event.stopPropagation();
                this.click(event, d);
            });
        
        nodeEnter.append('circle')
            .attr('r', 1e-6)
            .style('fill', d => d._children ? '#lightsteelblue' : '#fff');
        
        nodeEnter.append('text')
            .attr('dy', '.35em')
            .attr('x', d => d.children || d._children ? -13 : 13)
            .attr('text-anchor', d => d.children || d._children ? 'end' : 'start')
            .text(d => d.data.name)
            .style('fill-opacity', 1e-6);
        
        const nodeUpdate = nodeEnter.merge(node);
        
        nodeUpdate.transition()
            .duration(this.duration)
            .attr('transform', d => `translate(${d.y},${d.x})`);
        
        nodeUpdate.select('circle')
            .attr('r', d => {
                if (d.data.url) return 4;
                return d._children ? 6 : 4;
            })
            .style('fill', d => {
                if (d.data.url) return 'var(--color-primary)';
                return d._children ? '#lightsteelblue' : '#fff';
            })
            .attr('cursor', 'pointer');
        
        nodeUpdate.select('text')
            .style('fill-opacity', 1);
        
        const nodeExit = node.exit().transition()
            .duration(this.duration)
            .attr('transform', d => `translate(${source.y},${source.x})`)
            .remove();
        
        nodeExit.select('circle')
            .attr('r', 1e-6);
        
        nodeExit.select('text')
            .style('fill-opacity', 1e-6);
        
        const link = this.g.selectAll('path.link')
            .data(links, d => d.id);
        
        const linkEnter = link.enter().insert('path', 'g')
            .attr('class', 'link')
            .attr('d', d => {
                const o = {x: source.x0, y: source.y0};
                return this.diagonal(o, o);
            });
        
        const linkUpdate = linkEnter.merge(link);
        
        linkUpdate.transition()
            .duration(this.duration)
            .attr('d', d => this.diagonal(d, d.parent));
        
        link.exit().transition()
            .duration(this.duration)
            .attr('d', d => {
                const o = {x: source.x, y: source.y};
                return this.diagonal(o, o);
            })
            .remove();
        
        nodes.forEach(d => {
            d.x0 = d.x;
            d.y0 = d.y;
        });
    }
    
    click(event, d) {
        if (d.data.url) {
            // Force open link in new tab
            const link = document.createElement('a');
            link.href = d.data.url;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } else {
            if (d.children) {
                d._children = d.children;
                d.children = null;
            } else {
                d.children = d._children;
                d._children = null;
            }
            this.update(d);
        }
    }
    
    diagonal(s, d) {
        const path = `M ${s.y} ${s.x}
                     C ${(s.y + d.y) / 2} ${s.x},
                       ${(s.y + d.y) / 2} ${d.x},
                       ${d.y} ${d.x}`;
        return path;
    }
    
    handleResize() {
        const container = document.querySelector('.tree-container');
        this.width = container.clientWidth;
        this.height = container.clientHeight;
        
        this.svg
            .attr("width", this.width)
            .attr("height", this.height);
        
        this.tree.size([this.height - 40, this.width - 200]);
        
        this.update(this.root);
        this.centerTree();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new OTSecurityFramework();
});