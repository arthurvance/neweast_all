const TENANT_TECH_ILLUSTRATION_DATA_URI = `data:image/svg+xml;utf8,${encodeURIComponent(`
  <svg width="1600" height="900" viewBox="0 0 1600 900" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect width="1600" height="900" fill="url(#bg)"/>
    <g transform="translate(0, -60)">
      <path d="M0 70L360 0H1600V140L1240 260L0 70Z" fill="url(#shapeA)" fill-opacity="0.42"/>
      <path d="M0 820L340 660H1600V900H0V820Z" fill="url(#shapeB)" fill-opacity="0.45"/>
      <path d="M0 240L170 140V220L0 320V240Z" fill="#E7EFF9" fill-opacity="0.78"/>
      <path d="M1260 650L1600 480V590L1390 760L1260 650Z" fill="#E8F1FB" fill-opacity="0.8"/>
      <ellipse cx="560" cy="640" rx="360" ry="108" fill="url(#shadow)"/>
      <ellipse cx="560" cy="600" rx="290" ry="92" fill="#F9FCFF" stroke="#DCE7F4" stroke-width="8"/>
      <ellipse cx="560" cy="600" rx="228" ry="72" fill="#EDF4FF" stroke="#C8D8EE" stroke-width="6"/>
      <ellipse cx="560" cy="600" rx="160" ry="50" fill="url(#ringMain)" stroke="#1677FF" stroke-width="8"/>
      <ellipse cx="560" cy="600" rx="96" ry="30" fill="#F8FBFF" stroke="#9EC6FF" stroke-width="4"/>
      <path d="M488 504L560 462L632 504V570L560 612L488 570V504Z" fill="url(#pillarTop)"/>
      <path d="M488 504L560 462L560 528L488 570V504Z" fill="url(#pillarLeft)"/>
      <path d="M632 504L560 462V528L632 570V504Z" fill="url(#pillarRight)"/>
      <path d="M322 445L400 394L468 438L388 490L322 445Z" fill="url(#panelLeft)"/>
      <path d="M652 418L738 366L816 416L730 468L652 418Z" fill="url(#panelMid)"/>
      <path d="M612 330L700 280L780 326L692 378L612 330Z" fill="url(#panelTop)"/>
      <path d="M388 490V560L322 515V445L388 490Z" fill="#DCE9FC"/>
      <path d="M730 468V538L652 490V418L730 468Z" fill="#D9E8FE"/>
      <path d="M692 378V448L612 400V330L692 378Z" fill="#D9E7FD"/>
      <rect x="350" y="444" width="86" height="4" rx="2" fill="#70AEFF"/>
      <rect x="350" y="456" width="70" height="4" rx="2" fill="#B9D9FF"/>
      <rect x="680" y="418" width="98" height="4" rx="2" fill="#4096FF"/>
      <rect x="680" y="430" width="84" height="4" rx="2" fill="#8FC4FF"/>
      <path d="M644 330H744" stroke="#76B2FF" stroke-width="5" stroke-linecap="round"/>
      <path d="M664 344H734" stroke="#BDDFFF" stroke-width="5" stroke-linecap="round"/>
      <circle cx="874" cy="420" r="42" fill="url(#botBody)"/>
      <circle cx="874" cy="420" r="30" fill="#F7FBFF"/>
      <circle cx="874" cy="420" r="14" fill="#1677FF"/>
      <path d="M858 466H890" stroke="#CEDFF4" stroke-width="8" stroke-linecap="round"/>
      <path d="M398 706L450 680L510 716L458 742L398 706Z" fill="#E4EEFA"/>
      <path d="M398 706V742L458 778V742L398 706Z" fill="#D6E3F6"/>
      <path d="M458 742V778L510 752V716L458 742Z" fill="#C5D6EF"/>
      
      <!-- SCRM Node 1 -->
      <g transform="translate(180, 200)">
        <polygon points="40,0 80,20 80,60 40,80 0,60 0,20" fill="url(#nodeGradient1)"/>
        <polygon points="40,0 80,20 40,40 0,20" fill="#ffffff" opacity="0.6"/>
        <polygon points="40,40 80,20 80,60 40,80" fill="#a4cafe" opacity="0.6"/>
        <path d="M40,20 Q60,40 40,60 Q20,40 40,20" fill="#1d4ed8" opacity="0.7"/>
      </g>
      
      <!-- SCRM Node 2 -->
      <g transform="translate(900, 160)">
        <polygon points="50,0 100,25 100,75 50,100 0,75 0,25" fill="url(#nodeGradient2)"/>
        <polygon points="50,0 100,25 50,50 0,25" fill="#ffffff" opacity="0.5"/>
        <circle cx="50" cy="50" r="14" fill="#3b82f6"/>
        <circle cx="50" cy="50" r="8" fill="#eff6ff"/>
      </g>

      <!-- SCRM Node 3 -->
      <g transform="translate(240, 600)">
        <polygon points="30,0 60,15 60,45 30,60 0,45 0,15" fill="url(#nodeGradient3)"/>
        <polygon points="30,0 60,15 30,30 0,15" fill="#ffffff" opacity="0.7"/>
        <polygon points="30,30 60,15 60,45 30,60" fill="#93c5fd" opacity="0.5"/>
      </g>

      <!-- Connection Lines between SCRM Nodes and Main Hub -->
      <path d="M260,240 Q410,420 560,462" stroke="url(#nodeGradient1)" stroke-width="2" stroke-dasharray="8 4" fill="none" opacity="0.6"/>
      <path d="M950,210 Q730,320 632,504" stroke="url(#nodeGradient2)" stroke-width="3" stroke-dasharray="10 5" fill="none" opacity="0.5"/>
      <path d="M300,630 Q440,580 488,570" stroke="url(#nodeGradient3)" stroke-width="2" stroke-dasharray="6 3" fill="none" opacity="0.7"/>
      
      <!-- Floating Tech Orbs -->
      <circle cx="1060" cy="300" r="10" fill="#69B1FF"/>
      <circle cx="990" cy="250" r="8" fill="#A6D0FF"/>
      <circle cx="280" cy="510" r="9" fill="#C8E0FF"/>
      <circle cx="700" cy="250" r="7" fill="#8FC2FF"/>
      <circle cx="150" cy="280" r="16" fill="url(#botBody)" opacity="0.6"/>
      <circle cx="1380" cy="180" r="24" fill="url(#panelMid)" opacity="0.4"/>
      <circle cx="420" cy="120" r="6" fill="#1677FF" opacity="0.5"/>
      <circle cx="1200" cy="780" r="18" fill="url(#botBody)" opacity="0.7"/>

      <!-- Floating Panels -->
      <path d="M140 400L220 350L280 390L200 440Z" fill="url(#panelLeft)" opacity="0.5"/>
      <path d="M200 440V460L140 420V400Z" fill="#DCE9FC" opacity="0.5"/>
      <path d="M280 390V410L200 460V440Z" fill="#D9E8FE" opacity="0.5"/>
      
      <path d="M1250 240L1350 180L1430 230L1330 290Z" fill="url(#panelMid)" opacity="0.6"/>
      <path d="M1330 290V310L1250 260V240Z" fill="#DCE9FC" opacity="0.6"/>
      <path d="M1430 230V250L1330 310V290Z" fill="#D9E8FE" opacity="0.6"/>

      <!-- Abstract Data Tracks -->
      <path d="M-100 600 Q 300 800 600 500 T 1700 300" stroke="url(#panelTop)" stroke-width="2" fill="none" opacity="0.3" stroke-dasharray="10 10"/>
      <path d="M-100 640 Q 300 840 600 540 T 1700 340" stroke="url(#panelMid)" stroke-width="1" fill="none" opacity="0.2"/>
    </g>
    <defs>
      <linearGradient id="bg" x1="800" y1="0" x2="800" y2="900" gradientUnits="userSpaceOnUse">
        <stop stop-color="#F7FAFF"/>
        <stop offset="1" stop-color="#EDF3FB"/>
      </linearGradient>
      <linearGradient id="shapeA" x1="1400" y1="0" x2="0" y2="300" gradientUnits="userSpaceOnUse">
        <stop stop-color="#DBE8FA"/>
        <stop offset="1" stop-color="#EFF4FC"/>
      </linearGradient>
      <linearGradient id="shapeB" x1="1600" y1="640" x2="0" y2="900" gradientUnits="userSpaceOnUse">
        <stop stop-color="#E2EDFB"/>
        <stop offset="1" stop-color="#EEF4FC"/>
      </linearGradient>
      <radialGradient id="shadow" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(560 640) rotate(90) scale(108 360)">
        <stop stop-color="#8FA9CC" stop-opacity="0.26"/>
        <stop offset="1" stop-color="#8FA9CC" stop-opacity="0"/>
      </radialGradient>
      <linearGradient id="ringMain" x1="420" y1="560" x2="720" y2="640" gradientUnits="userSpaceOnUse">
        <stop stop-color="#1677FF"/>
        <stop offset="1" stop-color="#0958D9"/>
      </linearGradient>
      <linearGradient id="pillarTop" x1="560" y1="462" x2="560" y2="612" gradientUnits="userSpaceOnUse">
        <stop stop-color="#FFFFFF"/>
        <stop offset="1" stop-color="#EBF2FE"/>
      </linearGradient>
      <linearGradient id="pillarLeft" x1="524" y1="470" x2="500" y2="570" gradientUnits="userSpaceOnUse">
        <stop stop-color="#F6FAFF"/>
        <stop offset="1" stop-color="#DFE9F9"/>
      </linearGradient>
      <linearGradient id="pillarRight" x1="596" y1="470" x2="620" y2="570" gradientUnits="userSpaceOnUse">
        <stop stop-color="#E9F1FF"/>
        <stop offset="1" stop-color="#D2E1F8"/>
      </linearGradient>
      <linearGradient id="panelLeft" x1="468" y1="400" x2="318" y2="492" gradientUnits="userSpaceOnUse">
        <stop stop-color="#4096FF"/>
        <stop offset="1" stop-color="#91CAFF"/>
      </linearGradient>
      <linearGradient id="panelMid" x1="816" y1="370" x2="646" y2="472" gradientUnits="userSpaceOnUse">
        <stop stop-color="#1677FF"/>
        <stop offset="1" stop-color="#74B2FF"/>
      </linearGradient>
      <linearGradient id="panelTop" x1="780" y1="285" x2="608" y2="382" gradientUnits="userSpaceOnUse">
        <stop stop-color="#69B1FF"/>
        <stop offset="1" stop-color="#B7DCFF"/>
      </linearGradient>
      <linearGradient id="botBody" x1="832" y1="378" x2="916" y2="462" gradientUnits="userSpaceOnUse">
        <stop stop-color="#E4F0FF"/>
        <stop offset="1" stop-color="#CFE3FF"/>
      </linearGradient>
      <linearGradient id="nodeGradient1" x1="0" y1="0" x2="80" y2="80" gradientUnits="userSpaceOnUse">
        <stop stop-color="#93c5fd"/>
        <stop offset="1" stop-color="#3b82f6"/>
      </linearGradient>
      <linearGradient id="nodeGradient2" x1="0" y1="0" x2="100" y2="100" gradientUnits="userSpaceOnUse">
        <stop stop-color="#bfdbfe"/>
        <stop offset="1" stop-color="#2563eb"/>
      </linearGradient>
      <linearGradient id="nodeGradient3" x1="0" y1="0" x2="60" y2="60" gradientUnits="userSpaceOnUse">
        <stop stop-color="#60a5fa"/>
        <stop offset="1" stop-color="#1d4ed8"/>
      </linearGradient>
    </defs>
  </svg>
`)}`;

const PLATFORM_TECH_ILLUSTRATION_DATA_URI = `data:image/svg+xml;utf8,${encodeURIComponent(`
  <svg width="1600" height="900" viewBox="0 0 1600 900" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect width="1600" height="900" fill="url(#pbg)"/>
    <g transform="translate(0, -60)">
      <path d="M0 60L400 0H1600V120L1100 240L0 60Z" fill="url(#pshapeA)" fill-opacity="0.3"/>
      <path d="M0 840L400 680H1600V900H0V840Z" fill="url(#pshapeB)" fill-opacity="0.25"/>
      <ellipse cx="600" cy="620" rx="380" ry="120" fill="url(#pshadow)"/>
      <ellipse cx="600" cy="580" rx="300" ry="98" fill="#F4F7FB" stroke="#C9D6E8" stroke-width="6"/>
      <ellipse cx="600" cy="580" rx="220" ry="74" fill="#E2EBF5" stroke="#B0C4DF" stroke-width="4"/>
      <ellipse cx="600" cy="580" rx="140" ry="46" fill="url(#pringMain)" stroke="#2F54EB" stroke-width="6"/>
      
      <path d="M520 480L600 440L680 480V540L600 580L520 540V480Z" fill="url(#ppillarTop)"/>
      <path d="M520 480L600 440L600 500L520 540V480Z" fill="url(#ppillarLeft)"/>
      <path d="M680 480L600 440V500L680 540V480Z" fill="url(#ppillarRight)"/>
      
      <path d="M540 380L600 350L660 380V420L600 450L540 420V380Z" fill="url(#ppillarTop)"/>
      <path d="M540 380L600 350L600 390L540 420V380Z" fill="url(#ppillarLeft)"/>
      <path d="M660 380L600 350V390L660 420V380Z" fill="url(#ppillarRight)"/>

      <g transform="translate(850, 200)">
        <polygon points="50,0 100,20 100,70 50,110 0,70 0,20" fill="url(#nodeShieldGradient)"/>
        <polygon points="50,0 100,20 50,40 0,20" fill="#ffffff" opacity="0.6"/>
        <polygon points="50,40 100,20 100,70 50,110" fill="#a4cafe" opacity="0.4"/>
        <polygon points="50,30 80,45 80,75 50,95 20,75 20,45" fill="#1e3a8a" opacity="0.8"/>
      </g>
      
      <g transform="translate(200, 300)">
        <path d="M0 60L100 10L160 40L60 90Z" fill="url(#ppanelLeft)" opacity="0.6"/>
        <path d="M60 90V110L0 80V60Z" fill="#C5D3E8" opacity="0.6"/>
        <path d="M160 40V60L60 110V90Z" fill="#B2C5DF" opacity="0.6"/>
        <rect x="50" y="40" width="40" height="4" rx="2" fill="#2F54EB" transform="rotate(-26 50 40)"/>
        <rect x="60" y="55" width="30" height="4" rx="2" fill="#597EF7" transform="rotate(-26 60 55)"/>
      </g>

      <g transform="translate(1000, 500)">
        <path d="M0 40L80 0L140 30L60 70Z" fill="url(#ppanelRight)" opacity="0.7"/>
        <path d="M60 70V90L0 60V40Z" fill="#C5D3E8" opacity="0.7"/>
        <path d="M140 30V50L60 90V70Z" fill="#B2C5DF" opacity="0.7"/>
        <rect x="50" y="30" width="30" height="4" rx="2" fill="#1e40af" transform="rotate(-26 50 30)"/>
      </g>

      <path d="M660 380 Q780 290 850 255" stroke="url(#nodeShieldGradient)" stroke-width="3" stroke-dasharray="8 6" fill="none" opacity="0.8"/>
      <path d="M360 340 Q480 440 540 480" stroke="#597EF7" stroke-width="2" stroke-dasharray="6 4" fill="none" opacity="0.6"/>
    </g>
    <defs>
      <linearGradient id="pbg" x1="800" y1="0" x2="800" y2="900" gradientUnits="userSpaceOnUse">
        <stop stop-color="#F2F5F9"/>
        <stop offset="1" stop-color="#E5ECF4"/>
      </linearGradient>
      <linearGradient id="pshapeA" x1="1400" y1="0" x2="0" y2="300" gradientUnits="userSpaceOnUse">
        <stop stop-color="#C9D6ED"/>
        <stop offset="1" stop-color="#E2EAF4"/>
      </linearGradient>
      <linearGradient id="pshapeB" x1="1600" y1="640" x2="0" y2="900" gradientUnits="userSpaceOnUse">
        <stop stop-color="#CAD7ED"/>
        <stop offset="1" stop-color="#E2EBF4"/>
      </linearGradient>
      <radialGradient id="pshadow" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(600 620) rotate(90) scale(120 380)">
        <stop stop-color="#7A93B8" stop-opacity="0.3"/>
        <stop offset="1" stop-color="#7A93B8" stop-opacity="0"/>
      </radialGradient>
      <linearGradient id="pringMain" x1="460" y1="540" x2="740" y2="620" gradientUnits="userSpaceOnUse">
        <stop stop-color="#2F54EB"/>
        <stop offset="1" stop-color="#1D39C4"/>
      </linearGradient>
      <linearGradient id="ppillarTop" x1="600" y1="440" x2="600" y2="580" gradientUnits="userSpaceOnUse">
        <stop stop-color="#FFFFFF"/>
        <stop offset="1" stop-color="#E3EBF5"/>
      </linearGradient>
      <linearGradient id="ppillarLeft" x1="560" y1="450" x2="520" y2="540" gradientUnits="userSpaceOnUse">
        <stop stop-color="#F0F5FA"/>
        <stop offset="1" stop-color="#D6E2F0"/>
      </linearGradient>
      <linearGradient id="ppillarRight" x1="640" y1="450" x2="680" y2="540" gradientUnits="userSpaceOnUse">
        <stop stop-color="#E9F0F8"/>
        <stop offset="1" stop-color="#CDDDF0"/>
      </linearGradient>
      <linearGradient id="nodeShieldGradient" x1="0" y1="0" x2="100" y2="110" gradientUnits="userSpaceOnUse">
        <stop stop-color="#a5b4fc"/>
        <stop offset="1" stop-color="#3730a3"/>
      </linearGradient>
      <linearGradient id="ppanelLeft" x1="160" y1="40" x2="0" y2="100" gradientUnits="userSpaceOnUse">
        <stop stop-color="#597EF7"/>
        <stop offset="1" stop-color="#ADC6FF"/>
      </linearGradient>
      <linearGradient id="ppanelRight" x1="140" y1="30" x2="0" y2="80" gradientUnits="userSpaceOnUse">
        <stop stop-color="#2F54EB"/>
        <stop offset="1" stop-color="#85A5FF"/>
      </linearGradient>
    </defs>
  </svg>
`)}`;


export {
  TENANT_TECH_ILLUSTRATION_DATA_URI,
  PLATFORM_TECH_ILLUSTRATION_DATA_URI
};
