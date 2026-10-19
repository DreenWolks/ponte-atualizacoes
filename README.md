# Ponte — atualizações

Este repositório é usado pelo app **Ponte**:

- `latest.json` + `app-<versão>.asar`: atualização automática (o app baixa sozinho e confere o SHA-256).
- `auth/`: página de retorno do login do Mercado Livre (GitHub Pages). Endereço para cadastrar no DevCenter, em *URIs de redirect*:
  `https://dreenwolks.github.io/ponte-atualizacoes/auth/`
- `app/`: Ponte no celular (app web). O link com o código da equipe é gerado no Ponte do computador, em *Equipe → Celular*. A senha de cada pessoa nunca vai no link.
- `servidor/`: atualizações do **Ponte Servidor** (o servidor da equipe na sua VM). O servidor confere o SHA-256 de cada arquivo antes de usar.

Nenhuma senha, token ou dado da loja fica aqui.
