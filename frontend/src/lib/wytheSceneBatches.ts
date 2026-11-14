import * as THREE from 'three';
import type { AtlasNode } from '@/api/atlas';
import { createAtomicDeltahedra, createWytheAtomicMaterial, type AtomicMaterialOptions } from './wytheAtomicShader';
import type { EdgeLinePattern } from './wytheSceneLenses';
import type { PolygonRenderMode } from './wytheTheme';

export const DETAIL_DIAMETER_PX = 18;
export interface SceneRenderNode {
  node: AtlasNode;
  position: [number, number, number];
  scale: number;
  style: AtomicMaterialOptions;
}
export interface SceneRenderStats {
  total: number;
  inFrustum: number;
  detailed: number;
  overview: number;
}

/** Fit the actual graph bounds, including very wide or tall canvases. */
export function fitGraphCamera(camera: THREE.PerspectiveCamera, positions: Iterable<[number, number, number]>) {
  const bounds = new THREE.Box3();
  for (const position of positions) bounds.expandByPoint(new THREE.Vector3(...position));
  if (bounds.isEmpty()) bounds.set(new THREE.Vector3(-10, -18, -10), new THREE.Vector3(10, 18, 10));
  bounds.expandByScalar(5);
  const sphere = bounds.getBoundingSphere(new THREE.Sphere());
  const halfVertical = THREE.MathUtils.degToRad(camera.fov / 2);
  const halfHorizontal = Math.atan(Math.tan(halfVertical) * camera.aspect);
  const distance = sphere.radius / Math.sin(Math.min(halfVertical, halfHorizontal)) * 1.15;
  const direction = new THREE.Vector3(0.48, 0.42, 0.78).normalize();
  camera.position.copy(sphere.center).addScaledVector(direction, distance);
  camera.far = Math.max(520, distance + sphere.radius * 8);
  camera.updateProjectionMatrix();
  camera.lookAt(sphere.center);
  camera.updateMatrixWorld();
  return sphere.center;
}

type Shape = 'cache' | 'sqlGuard' | 'solver' | 'truth' | 'manipulate' | 'display';
const shapeFor = (node: AtlasNode): Shape => node.subkind === 'cache_store' ? 'cache'
  : node.subkind === 'sql_function' ? 'sqlGuard' : node.subkind === 'solver' ? 'solver' : node.tier;

/** Instanced glyphs nearby, one point batch at a distance; never a node quota. */
export function createBatchedNodes(records: SceneRenderNode[], mode: PolygonRenderMode) {
  const group = new THREE.Group();
  const geometries = mode === 'atomic' ? createAtomicDeltahedra() : {
    cache: new THREE.TorusGeometry(0.68, 0.22, 12, 24),
    sqlGuard: new THREE.OctahedronGeometry(0.72, 0),
    truth: new THREE.CylinderGeometry(0.75, 0.75, 0.9, 18),
    solver: new THREE.IcosahedronGeometry(0.92, 0),
    manipulate: new THREE.OctahedronGeometry(0.82, 0),
    display: new THREE.BoxGeometry(1.15, 0.55, 1.15),
  };
  const buckets = new Map<string, SceneRenderNode[]>();
  for (const record of records) {
    const { phase: _phase, ...style } = record.style;
    const key = JSON.stringify([shapeFor(record.node), style]);
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key)!.push(record);
  }
  const atomicMaterials: THREE.ShaderMaterial[] = [];
  const batches = [...buckets.values()].map((items) => {
    const { style, node } = items[0];
    const material = mode === 'atomic' ? createWytheAtomicMaterial({ ...style, phase: 0 })
      : new THREE.MeshStandardMaterial({
        color: style.barColor, emissive: style.barColor,
        emissiveIntensity: style.selected ? 0.95 : style.inCone ? 0.62 : style.dimmed ? 0.08 : 0.3,
        wireframe: style.hollow, transparent: style.dimmed, opacity: style.dimmed ? 0.2 : 1,
        roughness: 0.35, metalness: 0.2,
      });
    if (material instanceof THREE.ShaderMaterial) atomicMaterials.push(material);
    const geometry = geometries[shapeFor(node)];
    geometry.computeBoundingSphere();
    const mesh = new THREE.InstancedMesh(geometry, material, items.length);
    mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    mesh.count = 0;
    mesh.frustumCulled = false; // Compacted instances change whenever the camera moves.
    group.add(mesh);
    const instances: AtlasNode[] = [];
    const entries = items.map((item) => {
      const transform = new THREE.Object3D();
      transform.position.set(...item.position);
      if (item.node.subkind === 'cache_store') transform.rotation.x = Math.PI / 2;
      transform.scale.setScalar(item.scale);
      transform.updateMatrix();
      return { ...item, matrix: transform.matrix, center: transform.position,
        radius: geometry.boundingSphere!.radius * item.scale,
        color: new THREE.Color(item.style.barColor) };
    });
    return { mesh, entries, instances };
  });
  const usedGeometries = new Set(batches.map((batch) => batch.mesh.geometry));
  Object.values(geometries).forEach((geometry) => { if (!usedGeometries.has(geometry)) geometry.dispose(); });

  const pointGeometry = new THREE.BufferGeometry();
  const pointPositions = new THREE.Float32BufferAttribute(new Float32Array(records.length * 3), 3);
  const pointColors = new THREE.Float32BufferAttribute(new Float32Array(records.length * 3), 3);
  const pointStyles = new THREE.Float32BufferAttribute(new Float32Array(records.length * 2), 2);
  for (const attribute of [pointPositions, pointColors, pointStyles]) attribute.setUsage(THREE.DynamicDrawUsage);
  pointGeometry.setAttribute('position', pointPositions);
  pointGeometry.setAttribute('color', pointColors);
  pointGeometry.setAttribute('pointStyle', pointStyles);
  pointGeometry.setDrawRange(0, 0);
  const pointMaterial = new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, vertexColors: true,
    uniforms: { pixelRatio: { value: 1 } },
    vertexShader: `
      attribute vec2 pointStyle;
      uniform float pixelRatio;
      varying vec3 vColor;
      varying vec2 vStyle;
      void main() {
        vColor = color;
        vStyle = pointStyle;
        gl_PointSize = 5.0 * pixelRatio;
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
      }`,
    fragmentShader: `
      varying vec3 vColor;
      varying vec2 vStyle;
      void main() {
        float r = length(gl_PointCoord - vec2(0.5));
        if (r > 0.5 || (vStyle.y > 0.5 && r < 0.24)) discard;
        gl_FragColor = vec4(vColor, vStyle.x);
      }`,
  });
  const points = new THREE.Points(pointGeometry, pointMaterial);
  points.frustumCulled = false;
  group.add(points);
  const overviewHits: Array<{ node: AtlasNode; x: number; y: number; distance: number }> = [];
  const scratch = new THREE.Vector3();
  const view = new THREE.Vector3();
  const stats: SceneRenderStats = { total: records.length, inFrustum: 0, detailed: 0, overview: 0 };
  const renderedNodeIds = new Set<string>();
  const overviewNodeIds = new Set<string>();

  function update(camera: THREE.PerspectiveCamera, width: number, height: number, pixelRatio = 1) {
    camera.updateMatrixWorld();
    pointMaterial.uniforms.pixelRatio.value = pixelRatio;
    overviewHits.length = 0;
    renderedNodeIds.clear();
    overviewNodeIds.clear();
    stats.detailed = 0;
    stats.overview = 0;
    for (const batch of batches) {
      batch.instances.length = 0;
      for (const entry of batch.entries) {
        view.copy(entry.center).applyMatrix4(camera.matrixWorldInverse);
        if (-view.z < camera.near || -view.z > camera.far) continue;
        const diameter = entry.radius * height * camera.projectionMatrix.elements[5] / -view.z;
        scratch.copy(entry.center).project(camera);
        const detailed = diameter >= DETAIL_DIAMETER_PX || (entry.style.selected && diameter >= 6);
        const markerDiameter = detailed ? diameter : 5;
        if (Math.abs(scratch.x) > 1 + markerDiameter / width || Math.abs(scratch.y) > 1 + markerDiameter / height) continue;
        renderedNodeIds.add(entry.node.id);
        if (detailed) {
          batch.mesh.setMatrixAt(batch.instances.length, entry.matrix);
          batch.instances.push(entry.node);
          stats.detailed += 1;
        } else {
          const index = stats.overview++;
          overviewNodeIds.add(entry.node.id);
          pointPositions.setXYZ(index, ...entry.position);
          pointColors.setXYZ(index, entry.color.r, entry.color.g, entry.color.b);
          pointStyles.setXY(index, entry.style.dimmed ? 0.22 : 1, entry.style.hollow ? 1 : 0);
          overviewHits.push({ node: entry.node, x: (scratch.x + 1) * width / 2,
            y: (1 - scratch.y) * height / 2, distance: entry.center.distanceTo(camera.position) });
        }
      }
      batch.mesh.count = batch.instances.length;
      batch.mesh.instanceMatrix.needsUpdate = true;
      batch.mesh.boundingSphere = null;
    }
    pointGeometry.setDrawRange(0, stats.overview);
    for (const attribute of [pointPositions, pointColors, pointStyles]) attribute.needsUpdate = true;
    stats.inFrustum = stats.detailed + stats.overview;
    return { ...stats };
  }

  function pick(raycaster: THREE.Raycaster, x: number, y: number): AtlasNode | null {
    let node: AtlasNode | null = null;
    let distance = Infinity;
    for (const batch of batches) {
      const hit = raycaster.intersectObject(batch.mesh, false)[0];
      if (hit && hit.instanceId !== undefined && hit.distance < distance) {
        node = batch.instances[hit.instanceId];
        distance = hit.distance;
      }
    }
    for (const hit of overviewHits) {
      if (Math.hypot(hit.x - x, hit.y - y) <= 6 && hit.distance < distance) {
        node = hit.node;
        distance = hit.distance;
      }
    }
    return node;
  }
  return { group, atomicMaterials, stats, renderedNodeIds, overviewNodeIds, update, pick };
}

export interface SceneRenderEdge {
  start: [number, number, number];
  end: [number, number, number];
  color: number;
  opacity: number;
  pattern?: EdgeLinePattern;
}

const EDGE_PATTERN_SPANS: Record<EdgeLinePattern, ReadonlyArray<readonly [number, number]>> = {
  solid: [[0, 1]],
  dashed: [
    [0, 0.19],
    [0.27, 0.46],
    [0.54, 0.73],
    [0.81, 1],
  ],
  dotted: [
    [0, 0.05],
    [0.16, 0.21],
    [0.32, 0.37],
    [0.48, 0.53],
    [0.64, 0.69],
    [0.8, 0.85],
    [0.95, 1],
  ],
  broken_gap: [
    [0, 0.34],
    [0.66, 1],
  ],
};

function interpolatePoint(
  a: [number, number, number],
  b: [number, number, number],
  t: number,
): [number, number, number] {
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
}

export function createBatchedEdges(edges: SceneRenderEdge[]): THREE.Group {
  const group = new THREE.Group();
  const buckets = new Map<number, { positions: number[]; colors: number[] }>();
  const patternCounts: Record<EdgeLinePattern, number> = {
    solid: 0,
    dashed: 0,
    dotted: 0,
    broken_gap: 0,
  };
  const patternSegmentCounts: Record<EdgeLinePattern, number> = {
    solid: 0,
    dashed: 0,
    dotted: 0,
    broken_gap: 0,
  };

  for (const edge of edges) {
    if (!buckets.has(edge.opacity)) buckets.set(edge.opacity, { positions: [], colors: [] });
    const bucket = buckets.get(edge.opacity)!;
    const color = new THREE.Color(edge.color);
    const pattern: EdgeLinePattern = edge.pattern ?? 'solid';
    const spans = EDGE_PATTERN_SPANS[pattern];
    patternCounts[pattern] += 1;
    patternSegmentCounts[pattern] += spans.length;
    for (const [t0, t1] of spans) {
      const p0 = t0 === 0 ? edge.start : interpolatePoint(edge.start, edge.end, t0);
      const p1 = t1 === 1 ? edge.end : interpolatePoint(edge.start, edge.end, t1);
      bucket.positions.push(...p0, ...p1);
      bucket.colors.push(color.r, color.g, color.b, color.r, color.g, color.b);
    }
  }
  for (const [opacity, bucket] of buckets) {
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(bucket.positions, 3));
    geometry.setAttribute('color', new THREE.Float32BufferAttribute(bucket.colors, 3));
    group.add(new THREE.LineSegments(geometry, new THREE.LineBasicMaterial({
      vertexColors: true, transparent: true, opacity, depthWrite: false,
    })));
  }
  group.userData.patternCounts = patternCounts;
  group.userData.patternSegmentCounts = patternSegmentCounts;
  return group;
}
