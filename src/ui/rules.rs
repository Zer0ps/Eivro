use super::*;
use std::collections::BTreeSet;
use velum::policy::{self, Action, PolicyRule, RoutingProfile, Target};

pub(super) struct Editor {
    pub open: bool,
    profiles: Vec<RoutingProfile>,
    selected: usize,
    rows: BTreeSet<usize>,
    filter: String,
    add: bool,
    application: bool,
    input: String,
    action: Action,
    error: Option<String>,
    applications: Vec<(String, String)>,
}
impl Editor {
    pub fn new(settings: &Settings) -> Self {
        Self {
            open: true,
            profiles: settings.routing_profiles.clone(),
            selected: settings.selected_routing,
            rows: Default::default(),
            filter: String::new(),
            add: false,
            application: false,
            input: String::new(),
            action: Action::Direct,
            error: None,
            applications: applications(),
        }
    }
    #[cfg(feature = "qa")]
    pub fn open_add(&mut self, application: bool) {
        self.add = true;
        self.application = application;
    }
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        p: Palette,
    ) -> Option<(Vec<RoutingProfile>, usize)> {
        let mut applied = None;
        let mut open = self.open;
        egui::Window::new("Правила и профили").id(egui::Id::new("routing-editor"))
            .open(&mut open).collapsible(false).resizable(false).default_width(720.0)
            .min_width(560.0).max_width((ctx.content_rect().width()-96.0).max(360.0))
            .max_height((ctx.content_rect().height()-110.0).max(320.0))
            .anchor(Align2::CENTER_CENTER,Vec2::ZERO).show(ctx,|ui| {
                // Keep confirmation actions visible; only the editor body scrolls.
                egui::ScrollArea::vertical().id_salt("routing-editor-body")
                    .max_height((ctx.content_rect().height()-220.0).max(200.0))
                    .auto_shrink([false,true]).show(ui,|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Профиль").small().color(p.muted));
                    let old=self.selected;
                    egui::ComboBox::from_id_salt("edit-profile").width(210.0).selected_text(&self.profiles[self.selected].name)
                        .show_ui(ui,|ui| { for (i,profile) in self.profiles.iter().enumerate() { ui.selectable_value(&mut self.selected,i,&profile.name); } });
                    if old!=self.selected { self.rows.clear(); self.error=None; }
                    ui.menu_button("Профили",|ui| {
                        ui.label(RichText::new("Название профиля").small().color(p.muted));
                        ui.add(egui::TextEdit::singleline(&mut self.profiles[self.selected].name)
                            .char_limit(40).desired_width(220.0).margin(Vec2::new(10.0,8.0)));
                        ui.separator();
                        for (label,copy) in [("Новый профиль",false),("Создать копию",true)] {
                            if ui.add_enabled(self.profiles.len()<24,egui::Button::new(label)).clicked() {
                                let mut n=1;
                                let name=loop { let s=format!("Профиль {n}"); if !self.profiles.iter().any(|p|p.name==s) { break s; } n+=1; };
                                let rules=if copy { self.profiles[self.selected].rules.clone() } else { vec![] };
                                self.profiles.push(RoutingProfile {name,rules}); self.selected=self.profiles.len()-1; self.rows.clear(); ui.close();
                            }
                        }
                        if ui.add_enabled(self.profiles.len()>1,egui::Button::new("Удалить профиль")).clicked() {
                            self.profiles.remove(self.selected); self.selected=0; self.rows.clear(); ui.close();
                        }
                    });
                });
                ui.add_space(4.0);
                ui.separator();
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Найти правило…").margin(Vec2::new(10.0,8.0)).desired_width((ui.available_width()-166.0).max(160.0)));
                    if ui.add_sized([130.0,36.0],egui::Button::new(RichText::new(if self.add {"Закрыть форму"} else {"+ Добавить"}).color(if self.add {p.text}else{contrast(p.accent)}))
                        .fill(if self.add {p.raised}else{p.accent})).clicked() { self.add= !self.add; self.error=None; }
                });
                if self.add {
                    ui.add_space(4.0);
                    egui::Frame::new().fill(p.raised).stroke(Stroke::new(1.0_f32,p.accent.gamma_multiply(0.5)))
                        .corner_radius(12).inner_margin(16).show(ui,|ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            if ui.selectable_value(&mut self.application,false,"Адреса").changed() { self.input.clear(); }
                            if ui.selectable_value(&mut self.application,true,"Приложение").changed() { self.input.clear(); }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                                egui::ComboBox::from_id_salt("new-rule-action").width(150.0).selected_text(self.action.label()).show_ui(ui,|ui| {
                                    ui.selectable_value(&mut self.action,Action::Direct,Action::Direct.label());
                                    ui.selectable_value(&mut self.action,Action::Proxy,Action::Proxy.label());
                                });
                            });
                        });
                        if self.application {
                            egui::ComboBox::from_id_salt("application-choice").width(ui.available_width()-8.0).selected_text("Выбрать установленное приложение…")
                                .show_ui(ui,|ui| { for (name,path) in &self.applications { if ui.selectable_label(self.input==*path,name).clicked() { self.input=path.clone(); } } });
                            ui.add(egui::TextEdit::singleline(&mut self.input).hint_text("/usr/bin/firefox").margin(Vec2::new(12.0,10.0)).background_color(p.bg).desired_width(f32::INFINITY).char_limit(4096));
                            ui.label(RichText::new("Для TUN. Укажите исполняемый файл приложения; Flatpak и контейнеры требуют проверки пути процесса.").small().color(p.muted));
                        } else {
                            ui.add(egui::TextEdit::multiline(&mut self.input).id(egui::Id::new("bypass-input"))
                                .hint_text("example.com\n*.example.com\n192.168.1.0/24").margin(Vec2::new(12.0,10.0))
                                .background_color(p.bg).desired_rows(3).desired_width(f32::INFINITY).char_limit(65536));
                            ui.label(RichText::new("Можно вставить несколько адресов, по одному в строке.").small().color(p.muted));
                        }
                        ui.add_space(4.0);
                        if App::button(ui,"Добавить в профиль",ui.available_width(),p.accent,contrast(p.accent)).clicked() {
                            let profile=&mut self.profiles[self.selected];
                            let result=if self.application {
                                Target::application(&self.input).and_then(|target| {
                                    if profile.rules.len()>=256 { return Err("Максимум 256 правил.".into()); }
                                    if !profile.rules.iter().any(|r|r.target==target&&r.action==self.action) {
                                        profile.rules.push(PolicyRule {enabled:true,target,action:self.action});
                                    }
                                    Ok(1)
                                })
                            } else { profile.add_addresses(&self.input,self.action) };
                            match result { Ok(_)=>{self.input.clear();self.add=false;self.error=None;},Err(e)=>self.error=Some(e) }
                        }
                    });
                }
                ui.add_space(6.0);
                let filter=self.filter.to_lowercase();
                let visible:Vec<_>=self.profiles[self.selected].rules.iter().enumerate()
                    .filter(|(_,r)|r.target.value().to_lowercase().contains(&filter)).map(|(i,_)|i).collect();
                ui.horizontal_wrapped(|ui| {
                    let mut all= !visible.is_empty()&&visible.iter().all(|i|self.rows.contains(i));
                    if ui.checkbox(&mut all,"Выбрать все").changed() {
                        for i in &visible { if all { self.rows.insert(*i); } else { self.rows.remove(i); } }
                    }
                    ui.label(RichText::new("Первое совпадение сверху; остальное через VPN.").small().color(p.muted));
                });
                egui::ScrollArea::vertical().id_salt("policy-list").max_height(if self.add {if ctx.content_rect().height()<700.0 {80.0}else{150.0}}else{280.0})
                    .min_scrolled_height(if self.add {64.0}else{120.0}).auto_shrink([false,false]).show(ui,|ui| {
                        if visible.is_empty() {
                            ui.add_space(24.0);
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new(if filter.is_empty(){"В этом профиле всё через VPN"}else{"Ничего не найдено"}).size(18.0));
                                ui.label(RichText::new("Добавьте адрес или приложение, чтобы изменить маршрут.").color(p.muted));
                            });
                        }
                        for i in visible {
                            let mut selected=self.rows.contains(&i);
                            let rule=&mut self.profiles[self.selected].rules[i];
                            egui::Frame::new().fill(if selected {p.accent.gamma_multiply(0.13)}else{p.raised})
                                .stroke(Stroke::new(1.0_f32,if selected {p.accent}else{p.line}))
                                .corner_radius(8).inner_margin(egui::Margin::symmetric(10,4)).show(ui,|ui| {
                                ui.spacing_mut().interact_size.y=28.0;
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    if ui.checkbox(&mut selected,"").changed() {
                                        if selected {self.rows.insert(i);}else{self.rows.remove(&i);}
                                    }
                                    let label=rule.target.value();
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                                        if ui.small_button(if rule.enabled{"Вкл"}else{"Выкл"}).on_hover_text("Включить / выключить правило").clicked() {rule.enabled= !rule.enabled;}
                                        ui.label(RichText::new(rule.action.label()).small().color(p.muted));
                                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center),|ui| {
                                            ui.add(egui::Label::new(RichText::new(label).color(if rule.enabled{p.text}else{p.muted})).truncate()).on_hover_text(label);
                                        });
                                    });
                                });
                            });
                        }
                    });
                if !self.rows.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("Выбрано: {}",self.rows.len()));
                        for (label,enabled) in [("Включить",true),("Выключить",false)] {
                            if ui.button(label).clicked() {for i in &self.rows {self.profiles[self.selected].rules[*i].enabled=enabled;}}
                        }
                        ui.menu_button("Маршрут",|ui| {
                            for action in [Action::Direct,Action::Proxy] {
                                if ui.button(action.label()).clicked() {
                                    for i in &self.rows {self.profiles[self.selected].rules[*i].action=action;}
                                    ui.close();
                                }
                            }
                        });
                        if ui.button("Удалить выбранные").clicked() {
                            let mut i=0; self.profiles[self.selected].rules.retain(|_|{let keep= !self.rows.contains(&i);i+=1;keep}); self.rows.clear();
                        }
                        if self.rows.len()==1 {
                            let i=*self.rows.first().unwrap();
                            for (label,next) in [("Выше",i.checked_sub(1)),("Ниже",i.checked_add(1).filter(|n|*n<self.profiles[self.selected].rules.len()))] {
                                if ui.add_enabled(next.is_some(),egui::Button::new(label)).clicked() && let Some(next)=next {
                                    self.profiles[self.selected].rules.swap(i,next);self.rows.clear();self.rows.insert(next);
                                }
                            }
                        }
                        if ui.button("Снять выбор").clicked(){self.rows.clear();}
                    });
                }
                });
                ui.add_space(4.0);
                ui.separator();
                if let Some(error)=&self.error { ui.colored_label(Color32::from_rgb(223,133,114),error); }
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Изменения применятся вместе.").small().color(p.muted));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
                        if App::button(ui,"Применить",140.0,p.accent,contrast(p.accent)).clicked() {
                            match policy::validate_profiles(&self.profiles,self.selected) {
                                Ok(())=>applied=Some((self.profiles.clone(),self.selected)),
                                Err(e)=>self.error=Some(e),
                            }
                        }
                        if App::button(ui,"Отмена",110.0,p.raised,p.text).clicked() { self.open=false; }
                    });
                });
            });
        self.open &= open;
        applied
    }
}

/// Read desktop entries as data; never execute their commands or expand a shell.
fn applications() -> Vec<(String, String)> {
    let mut dirs = vec![
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/applications"));
    }
    let mut apps = Vec::new();
    for dir in dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten().take(2048) {
                let path = entry.path();
                if path.extension().is_none_or(|s| s != "desktop")
                    || !entry.metadata().is_ok_and(|m| m.len() <= 65536)
                {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(path) else {
                    continue;
                };
                let mut name = None;
                let mut executable = None;
                let mut active = false;
                let mut hidden = false;
                for line in text.lines() {
                    if line.starts_with('[') {
                        active = line == "[Desktop Entry]";
                    }
                    if !active {
                        continue;
                    }
                    if line == "NoDisplay=true" || line == "Hidden=true" {
                        hidden = true;
                    }
                    if let Some(s) = line.strip_prefix("Name=") {
                        name = Some(
                            s.chars()
                                .filter(|c| !c.is_control())
                                .take(80)
                                .collect::<String>(),
                        );
                    }
                    if let Some(s) = line.strip_prefix("Exec=") {
                        let program = if let Some(s) = s.strip_prefix('"') {
                            s.split('"').next().unwrap_or("")
                        } else {
                            s.split_whitespace().next().unwrap_or("")
                        };
                        if program.starts_with('/') {
                            executable = Some(program.to_owned());
                        } else if !["env", "flatpak", "sh", "bash", "xdg-open"].contains(&program) {
                            executable = ["/usr/bin", "/usr/local/bin", "/bin"]
                                .iter()
                                .map(|p| PathBuf::from(p).join(program))
                                .find(|p| p.is_file())
                                .map(|p| p.to_string_lossy().into_owned());
                        }
                    }
                }
                if !hidden
                    && let (Some(name), Some(path)) = (name, executable)
                    && Target::application(&path).is_ok()
                {
                    apps.push((name, path));
                }
            }
        }
    }
    apps.sort_by_key(|(name, _)| name.to_lowercase());
    apps.dedup();
    apps
}
