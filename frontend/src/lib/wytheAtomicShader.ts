import * as THREE from 'three';

function attachBarycentrics(indexedOrNonIndexed: THREE.BufferGeometry): THREE.BufferGeometry {
  const geo = indexedOrNonIndexed.index
    ? indexedOrNonIndexed.toNonIndexed()
    : indexedOrNonIndexed.clone();
  const pos = geo.getAttribute('position');
  const count = pos.count;
  const bary = new Float32Array(count * 3);
  for (let i = 0; i < count; i += 3) {
    const base = i * 3;
    bary[base] = 1;
    bary[base + 4] = 1;
    bary[base + 8] = 1;
  }
  geo.setAttribute('aBary', new THREE.BufferAttribute(bary, 3));
  geo.computeVertexNormals();
  return geo;
}

export function createDisplayHexGeometry(radius = 0.96, halfHeight = 0.28): THREE.BufferGeometry {
  const top: [number, number, number] = [0, halfHeight, 0];
  const bot: [number, number, number] = [0, -halfHeight, 0];
  const ring: Array<[number, number, number]> = [];
  for (let i = 0; i < 6; i += 1) {
    const a = (i * Math.PI) / 3;
    ring.push([Math.cos(a) * radius, 0, -Math.sin(a) * radius]);
  }
  const positions: number[] = [];
  for (let i = 0; i < 6; i += 1) {
    const r0 = ring[i];
    const r1 = ring[(i + 1) % 6];
    positions.push(...top, ...r0, ...r1);
    positions.push(...bot, ...r1, ...r0);
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  return attachBarycentrics(geo);
}

export function createAtomicDeltahedra() {
  return {
    display: createDisplayHexGeometry(1.22, 0.38),
    manipulate: attachBarycentrics(new THREE.OctahedronGeometry(1.16, 0)),
    solver: attachBarycentrics(new THREE.IcosahedronGeometry(1.24, 0)),
    truth: attachBarycentrics(new THREE.IcosahedronGeometry(1.18, 0)),
    sqlGuard: attachBarycentrics(new THREE.OctahedronGeometry(0.92, 0)),
    cache: attachBarycentrics(new THREE.TorusGeometry(0.9, 0.32, 6, 12)),
  };
}

const VERTEX_SHADER = /* glsl */ `
attribute vec3 aBary;
varying vec3 vBary;
varying vec3 vViewNormal;
varying float vPhaseOffset;

void main() {
  vBary = aBary;
  vec4 localPosition = vec4(position, 1.0);
  vec3 localNormal = normal;
  vPhaseOffset = 0.0;
  #ifdef USE_INSTANCING
    localPosition = instanceMatrix * localPosition;
    localNormal = mat3(instanceMatrix) * localNormal;
    vPhaseOffset = dot(instanceMatrix[3].xyz, vec3(0.17, 0.31, 0.67));
  #endif
  vViewNormal = normalize(normalMatrix * localNormal);
  gl_Position = projectionMatrix * modelViewMatrix * localPosition;
}
`;

const FRAGMENT_SHADER = /* glsl */ `
uniform float uTime;
uniform float uPhase;
uniform float uBreathAmp;
uniform float uBreathSpeed;
uniform float uHollow;
uniform float uOpacity;
uniform float uEmissiveGain;
uniform vec3 uBarColor;
uniform vec3 uInquiryColor;

varying vec3 vBary;
varying vec3 vViewNormal;
varying float vPhaseOffset;

const float PI = 3.14159265359;

float sdSegment(vec2 p, vec2 a, vec2 b) {
  vec2 pa = p - a;
  vec2 ba = b - a;
  float h = clamp(dot(pa, ba) / dot(ba, ba), 0.0, 1.0);
  return length(pa - ba * h);
}

float sdRoundedBox(vec2 p, vec2 halfSize, float r) {
  vec2 q = abs(p) - halfSize + vec2(r);
  return min(max(q.x, q.y), 0.0) + length(max(q, 0.0)) - r;
}

float sdQuestionStroke(vec2 u) {
  vec2 p0 = vec2(25.0, -10.4);
  vec2 p1 = vec2(30.6, -9.2);
  vec2 p2 = vec2(34.9, -5.2);
  vec2 p3 = vec2(36.2, 0.3);
  vec2 p4 = vec2(34.7, 5.9);
  vec2 p5 = vec2(30.2, 9.8);
  vec2 p6 = vec2(25.4, 10.3);
  vec2 p7 = vec2(20.6, 6.8);
  vec2 p8 = vec2(17.7, 1.9);
  vec2 p9 = vec2(15.2, 0.0);

  float d = sdSegment(u, p0, p1);
  d = min(d, sdSegment(u, p1, p2));
  d = min(d, sdSegment(u, p2, p3));
  d = min(d, sdSegment(u, p3, p4));
  d = min(d, sdSegment(u, p4, p5));
  d = min(d, sdSegment(u, p5, p6));
  d = min(d, sdSegment(u, p6, p7));
  d = min(d, sdSegment(u, p7, p8));
  d = min(d, sdSegment(u, p8, p9));
  return d;
}

void main() {
  vec3 b = gl_FrontFacing ? vBary : vec3(vBary.y, vBary.x, vBary.z);

  vec2 t0 = vec2(-12.35, 17.5);
  vec2 t1 = vec2(112.35, 17.5);
  vec2 t2 = vec2(50.0, 125.5);
  vec2 p = b.x * t0 + b.y * t2 + b.z * t1 - vec2(50.0, 53.5);

  float sector = 2.0 * PI / 3.0;
  float ang = mod(atan(p.x, -p.y) + PI / 3.0, sector) - PI / 3.0;
  vec2 u = length(p) * vec2(cos(ang), sin(ang));

  float wave = sin(uTime * uBreathSpeed + uPhase + vPhaseOffset);
  float rIn = (uHollow > 0.5) ? 27.2 : (22.8 + uBreathAmp * wave);
  float rOut = (uHollow > 0.5) ? 35.0 : (rIn + 11.0);
  float hl = 23.5 + (rIn - 22.8) * 0.25;
  float qScale = clamp(0.74 - (rIn - 22.8) * 0.018, 0.65, 0.90);

  vec2 uQ = u / qScale;
  float dHook = (sdQuestionStroke(uQ) - 2.9) * qScale;
  float dDot = (length(uQ - vec2(8.4, 0.0)) - 3.5) * qScale;
  float dInquiry = min(dHook, dDot);

  float dCutHook = (sdQuestionStroke(uQ) - 5.4) * qScale;
  float dCutDot = (length(uQ - vec2(8.4, 0.0)) - 6.0) * qScale;
  float dCollar = min(dCutHook, dCutDot);

  float barMid = 0.5 * (rIn + rOut);
  float barHalfW = 0.5 * (rOut - rIn);
  float dBar = sdRoundedBox(u - vec2(barMid, 0.0), vec2(barHalfW, hl), 3.0);
  float dBarCut = max(dBar, -dCollar);

  float dSymbol = min(dBarCut, dInquiry);
  float dShape = (uHollow > 0.5) ? (abs(dSymbol + 0.85) - 0.85) : dSymbol;

  float aa = max(fwidth(dShape) * 1.15, 0.35);
  float alpha = 1.0 - smoothstep(-aa, aa, dShape);
  float faceFactor = gl_FrontFacing ? 1.0 : 0.28;
  float finalAlpha = alpha * uOpacity * faceFactor;
  if (finalAlpha < 0.04) {
    discard;
  }

  float isInq = 1.0 - smoothstep(-aa, aa, dInquiry - dBarCut);
  vec3 baseCol = mix(uBarColor, uInquiryColor, isInq);
  float rim = 0.78 + 0.22 * abs(vViewNormal.z);
  gl_FragColor = vec4(baseCol * rim * uEmissiveGain, finalAlpha);
}
`;

export interface AtomicMaterialOptions {
  barColor: THREE.ColorRepresentation;
  inquiryColor: THREE.ColorRepresentation;
  hollow: boolean;
  flagged: boolean;
  dimmed: boolean;
  selected: boolean;
  inCone: boolean;
  phase: number;
}

export function createWytheAtomicMaterial(opts: AtomicMaterialOptions): THREE.ShaderMaterial {
  return new THREE.ShaderMaterial({
    vertexShader: VERTEX_SHADER,
    fragmentShader: FRAGMENT_SHADER,
    side: THREE.DoubleSide,
    transparent: true,
    depthWrite: !opts.dimmed,
    uniforms: {
      uTime: { value: 0 },
      uPhase: { value: opts.phase },
      uBreathAmp: { value: opts.hollow ? 0.0 : opts.flagged ? 3.4 : 1.5 },
      uBreathSpeed: { value: opts.flagged ? 2.6 : 1.35 },
      uHollow: { value: opts.hollow ? 1.0 : 0.0 },
      uOpacity: { value: opts.dimmed ? 0.22 : 1.0 },
      uEmissiveGain: { value: opts.selected ? 1.35 : opts.inCone ? 1.16 : 1.0 },
      uBarColor: { value: new THREE.Color(opts.barColor) },
      uInquiryColor: { value: new THREE.Color(opts.inquiryColor) },
    },
  });
}
