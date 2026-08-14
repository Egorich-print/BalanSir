<script>
  import { badgeClass } from '../lib/status.js';
  export let status = 'unavailable';
  export let title = '';
</script>

<span class="badge {badgeClass(status)}">
  {title || status}
</span>

<style>
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .status-healthy { background: #123b2a; color: #4cd07d; }
  .status-degraded { background: #4a3410; color: #ffb454; }
  .status-recovering { background: #12344a; color: #4cc9f0; }
  .status-blocked { background: #4a1210; color: #ff6b6b; }
  .status-fallback { background: #33264a; color: #c77dff; }
  .status-disabled { background: #2a2a2a; color: #8a8a8a; }
  .status-unavailable { background: #1f1f1f; color: #666; }
</style>
