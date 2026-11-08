'use strict';
// Presentation-only extension. No agent execution or approval is triggered here.
function toggleWorkspaceMenu(){
 const sidebar=document.getElementById('workspace-sidebar');
 const open=sidebar.classList.toggle('menu-open');
 document.querySelector('.menu-toggle').setAttribute('aria-expanded',String(open));
}
(function(){
 const labels={overview:'Tổng quan',monitor:'Phiên hoạt động',cti:'Báo cáo CTI',iocs:'Chỉ báo IOC',mitre:'MITRE ATT&CK',skills:'Kỹ năng & Hunter',rules:'Luật phát hiện',tools:'Danh mục công cụ',health:'Sức khỏe hệ thống'};
 const nativeSwitch=window.switchView;
 window.switchView=function(view){
  nativeSwitch(view);
  const heading=document.getElementById('page-heading');
  heading.textContent=labels[view]||'CTI Workspace';
  heading.title=heading.textContent;
  document.querySelectorAll('.nav-item').forEach(el=>{
   if(el.id==='nav-'+view)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');
  });
  document.getElementById('workspace-sidebar').classList.remove('menu-open');
  document.querySelector('.menu-toggle').setAttribute('aria-expanded','false');
 };
 function message(text){
  let banner=document.getElementById('workspace-load-error');
  if(!banner){banner=document.createElement('div');banner.id='workspace-load-error';banner.className='workspace-error';banner.setAttribute('role','alert');document.querySelector('.content-body').prepend(banner);}
  banner.textContent=text;
 }
 async function refreshReview(){
  try{
   const [overview,skills]=await Promise.all([fetch('/api/dashboard/overview'),fetch('/api/skills')]);
   if(!overview.ok||!skills.ok)throw new Error('API không khả dụng');
   const data=await overview.json(),items=await skills.json();
  const elRules=document.getElementById('queue-rules');if(elRules)elRules.textContent=data.kpis.awaiting_approval_rules;
  const elRuns=document.getElementById('queue-runs');if(elRuns)elRuns.textContent=data.kpis.running_tasks;
  const elSkills=document.getElementById('queue-skills');if(elSkills)elSkills.textContent=items.filter(s=>s.approval_status==='pending_review').length;
   document.querySelectorAll('.queue-item strong').forEach(el=>el.dataset.zero=String(el.textContent==='0'));
   document.getElementById('workspace-load-error')?.remove();
  }catch(error){console.error('refreshReview error:', error);message('Không thể cập nhật dữ liệu. Kiểm tra backend local và thử “Cập nhật dữ liệu”.');}
 }
 const nativeOverview=window.loadOverview;
 window.loadOverview=async function(...args){await Promise.all([nativeOverview(...args),refreshReview()]);};
 document.addEventListener('keydown',event=>{
  if(event.key==='Escape'){
   document.getElementById('workspace-sidebar').classList.remove('menu-open');
   document.querySelector('.menu-toggle').setAttribute('aria-expanded','false');
  }
 });
 document.addEventListener('DOMContentLoaded',()=>{
  if(typeof Chart==='undefined'){
   // CDN failure must not prevent real tables and KPI data from rendering.
   window.renderOverviewCharts=function(){
    for(const id of ['chart-timeline','chart-distribution']){
     const canvas=document.getElementById(id);
     if(canvas&&!canvas.parentElement.querySelector('.chart-unavailable')){
      const note=document.createElement('div');note.className='chart-unavailable';note.textContent='Chưa tải được thư viện biểu đồ. Dữ liệu bảng vẫn khả dụng.';canvas.hidden=true;canvas.parentElement.append(note);
     }
    }
   };
   loadOverview(true);
  }
  refreshReview();
 });
})();
